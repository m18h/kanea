// SPDX-License-Identifier: (GPL-2.0-only OR MIT)

//go:build ignore
// (The constraint above keeps the Go toolchain from treating this file as
// a cgo input: go/build reads build constraints in .c files too.)

/*
 * kanea.c; the Kanea datapath (PRD v1.36 §5.2.5, dual-stack since v1.41):
 * four programs, one compile unit.
 *
 *   kanea_connect4       cgroup/connect4  connect-time service LB
 *   kanea_connect6       cgroup/connect6  its v6 twin (+ v4-mapped dials)
 *   kanea_to_container   tc               policy on the veth toward an alloc
 *   kanea_from_container tc               egress guard on the veth from an alloc
 *
 * IP is identity: kanead allocates every address and writes identity_v4 /
 * identity_v6 itself, so there is no identity protocol and no settle
 * window. Policy is SYN-gated and stateless: non-SYN TCP passes so
 * cross-project allow_from replies flow without a conntrack. Established
 * connections never consult a map; backend sets change by generation flip
 * (see dpmap.FlipPlan).
 *
 * The v6 maps are separate rather than widened v4 maps (v1.41): widening a
 * pinned map's key changes its ABI, and ErrMapIncompatible would wipe every
 * node's pins at upgrade; v4-only nodes included. When v6 is not
 * configured (config6's mask is all-zero, an ARRAY map's birth state), the
 * tc programs DROP ETH_P_IPV6 outright: the kernel assigns link-locals
 * regardless, and unpoliced IPv6 between a container and a host service
 * bound to :: was a policy bypass, not compatibility.
 *
 * No bpf_trace_printk anywhere: a drop is counted in stats_drops /
 * stats_drops6, never logged from the datapath.
 */

#include "headers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* ---- drop reasons (mirrored by dpmap.DropReason*) ---------------------- */

#define DROP_POLICY 1
#define DROP_METADATA 2
#define DROP_NO_BACKEND 3
#define DROP_VIP_LEAK 4
#define DROP_LINK_LOCAL 5
#define DROP_SPOOF 6
#define DROP_MULTICAST 7
#define DROP_ETHERTYPE 8

/* identity.flags bit 0: the address belongs to the host, not an alloc */
#define IDENTITY_FLAG_HOST 1

/* ---- map key/value layouts (mirrored by dpmap; sizes are pinned there) - */

struct svc_key {
	__be32 vip;
	__be16 port;
	__u8 proto;
	__u8 pad;
}; /* 8 bytes */

struct svc_val {
	__u16 svc_id;
	__u16 count;
	__u32 gen;
}; /* 8 bytes */

struct backend_key {
	__u16 svc_id;
	__u16 index;
	__u32 gen;
}; /* 8 bytes */

struct backend_val {
	__be32 ip;
	__be16 port;
	__u16 pad;
}; /* 8 bytes */

struct identity {
	__u32 project_id;
	__u32 service_id;
	__u32 flags;
}; /* 12 bytes */

struct allow_key {
	__u32 dst_service_id;
	__u32 src_service_id;
}; /* 8 bytes */

struct ep_stats {
	__u64 rx_bytes;
	__u64 rx_pkts;
	__u64 tx_bytes;
	__u64 tx_pkts;
}; /* 32 bytes */

struct drop_key {
	__be32 dst_ip;
	__u8 reason;
	__u8 pad[3];
}; /* 8 bytes */

struct dp_config {
	__be32 service_cidr_net;
	__be32 service_cidr_mask;
}; /* 8 bytes */

/* One prefix as net+mask: cluster_v4's value (v1.65). Its own struct
 * rather than a widened dp_config: widening a pinned map's value changes
 * its ABI, and ErrMapIncompatible would wipe every node's pins at upgrade
 * (the v1.41 rule). */
struct dp_cidr {
	__be32 net;
	__be32 mask;
}; /* 8 bytes */

/* ---- the v6 twins (v1.41). svc_val, backend_key, identity and allow_key
 * are address-family-neutral and shared; only what carries an address gets
 * a wider sibling. */

struct svc_key6 {
	__be32 vip[4];
	__be16 port;
	__u8 proto;
	__u8 pad;
}; /* 20 bytes */

struct backend_val6 {
	__be32 ip[4];
	__be16 port;
	__u16 pad;
}; /* 20 bytes */

struct drop_key6 {
	__be32 dst_ip[4];
	__u8 reason;
	__u8 pad[3];
}; /* 20 bytes */

struct dp_config6 {
	__be32 net[4];
	__be32 mask[4];
}; /* 32 bytes */

/* cluster_v6's value: dp_cidr's wide sibling. */
struct dp_cidr6 {
	__be32 net[4];
	__be32 mask[4];
}; /* 32 bytes */

/* ---- maps -------------------------------------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct svc_key);
	__type(value, struct svc_val);
} svc_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct backend_key);
	__type(value, struct backend_val);
} svc_backends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __be32); /* pod ip */
	__type(value, struct identity);
} identity_v4 SEC(".maps");

/* veth_src binds a host veth (by ifindex) to the one source address kanead
 * assigned it (K-09, v1.77): from_container drops a packet whose claimed
 * source is anything else, so the identity a destination's policy evaluates
 * can never be forged from inside the alloc (IP_FREEBIND needs no
 * capability, so dropping CAP_NET_RAW does not close forgery on its own).
 * Additive beside the existing maps, per the v1.41 ABI rule; a missing
 * entry fails closed, like an identity miss. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);    /* host veth ifindex */
	__type(value, __be32); /* assigned pod ip */
} veth_src SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct allow_key);
	__type(value, __u8);
} allow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u16); /* svc_id */
	__type(value, __u64); /* connects */
} stats_svc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, __be32); /* pod ip */
	__type(value, struct ep_stats);
} stats_ep SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct drop_key);
	__type(value, __u64);
} stats_drops SEC(".maps");

/* The service CIDR is data, not a compiled constant: one entry, written by
 * kanead at load time. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dp_config);
} config SEC(".maps");

/* The cluster CIDR (v1.65): what to_container treats as internal. A source
 * inside it with no identity is an alloc mid-teardown: fail closed. One
 * outside it is the world answering an egress connection the host un-NATed,
 * and passes. The all-zero birth state reads as "no cluster configured",
 * which drops: a program ahead of its configuration keeps the pre-v1.65
 * behavior rather than opening up. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dp_cidr);
} cluster_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct svc_key6);
	__type(value, struct svc_val);
} svc_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct backend_key);
	__type(value, struct backend_val6);
} svc_backends6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct in6_addr); /* pod ipv6 */
	__type(value, struct identity);
} identity_v6 SEC(".maps");

/* The v6 twin of veth_src (v1.77). A veth with no entry (a v4-only
 * attachment adopted across the v1.41 upgrade) has no v6 source at all:
 * the miss drops, which is exactly right for it. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);          /* host veth ifindex */
	__type(value, struct in6_addr); /* assigned pod ipv6 */
} veth_src6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct in6_addr); /* pod ipv6 */
	__type(value, struct ep_stats);
} stats_ep6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct drop_key6);
	__type(value, __u64);
} stats_drops6 SEC(".maps");

/* config6's all-zero mask doubles as the v6 enable switch: unwritten (an
 * ARRAY map is zero-filled) means v6 is off and the tc programs drop
 * ETH_P_IPV6 outright. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dp_config6);
} config6 SEC(".maps");

/* cluster_v4's v6 sibling (v1.65). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dp_cidr6);
} cluster_v6 SEC(".maps");

/* ---- per-CPU counter bumps --------------------------------------------- */
/* Pattern: lookup; if present (*v)++; else update with 1 (BPF_ANY). The
 * value is per-CPU, so the read-modify-write races with nothing. */

static __always_inline void count_drop(__be32 dst_ip, __u8 reason)
{
	struct drop_key key = {
		.dst_ip = dst_ip,
		.reason = reason,
		.pad = { 0, 0, 0 },
	};
	__u64 *v = bpf_map_lookup_elem(&stats_drops, &key);

	if (v) {
		(*v)++;
	} else {
		__u64 one = 1;

		/* A full map folds into the overflow key (zero address, same
		 * reason): the drop stays counted rather than vanishing, and the
		 * fold itself is the count of it (K-29). The fold can only fail
		 * when even the overflow key has no slot, which is the map saying
		 * it is entirely full of drops. */
		if (bpf_map_update_elem(&stats_drops, &key, &one, BPF_ANY) < 0) {
			struct drop_key over = {
				.dst_ip = 0, .reason = reason, .pad = { 0, 0, 0 },
			};
			__u64 *ov = bpf_map_lookup_elem(&stats_drops, &over);

			if (ov)
				(*ov)++;
			else
				bpf_map_update_elem(&stats_drops, &over, &one,
						    BPF_ANY);
		}
	}
}

static __always_inline void count_connect(__u16 svc_id)
{
	__u64 *v = bpf_map_lookup_elem(&stats_svc, &svc_id);

	if (v) {
		(*v)++;
	} else {
		__u64 one = 1;

		bpf_map_update_elem(&stats_svc, &svc_id, &one, BPF_ANY);
	}
}

static __always_inline void count_rx(__be32 pod_ip, __u64 bytes)
{
	struct ep_stats *s = bpf_map_lookup_elem(&stats_ep, &pod_ip);

	if (s) {
		s->rx_bytes += bytes;
		s->rx_pkts++;
	} else {
		struct ep_stats init = { .rx_bytes = bytes, .rx_pkts = 1 };

		bpf_map_update_elem(&stats_ep, &pod_ip, &init, BPF_ANY);
	}
}

static __always_inline void count_tx(__be32 pod_ip, __u64 bytes)
{
	struct ep_stats *s = bpf_map_lookup_elem(&stats_ep, &pod_ip);

	if (s) {
		s->tx_bytes += bytes;
		s->tx_pkts++;
	} else {
		struct ep_stats init = { .tx_bytes = bytes, .tx_pkts = 1 };

		bpf_map_update_elem(&stats_ep, &pod_ip, &init, BPF_ANY);
	}
}

static __always_inline void count_drop6(const struct in6_addr *dst, __u8 reason)
{
	struct drop_key6 key = {
		.reason = reason,
		.pad = { 0, 0, 0 },
	};

	key.dst_ip[0] = dst->s6_addr32[0];
	key.dst_ip[1] = dst->s6_addr32[1];
	key.dst_ip[2] = dst->s6_addr32[2];
	key.dst_ip[3] = dst->s6_addr32[3];

	__u64 *v = bpf_map_lookup_elem(&stats_drops6, &key);

	if (v) {
		(*v)++;
	} else {
		__u64 one = 1;

		/* Full map: fold into the zero-address overflow key for the same
		 * reason (K-29), as in count_drop. */
		if (bpf_map_update_elem(&stats_drops6, &key, &one, BPF_ANY) < 0) {
			struct drop_key6 over = {
				.reason = reason, .pad = { 0, 0, 0 },
			};
			__u64 *ov = bpf_map_lookup_elem(&stats_drops6, &over);

			if (ov)
				(*ov)++;
			else
				bpf_map_update_elem(&stats_drops6, &over, &one,
						    BPF_ANY);
		}
	}
}

static __always_inline void count_rx6(const struct in6_addr *pod_ip, __u64 bytes)
{
	struct ep_stats *s = bpf_map_lookup_elem(&stats_ep6, pod_ip);

	if (s) {
		s->rx_bytes += bytes;
		s->rx_pkts++;
	} else {
		struct ep_stats init = { .rx_bytes = bytes, .rx_pkts = 1 };

		bpf_map_update_elem(&stats_ep6, pod_ip, &init, BPF_ANY);
	}
}

static __always_inline void count_tx6(const struct in6_addr *pod_ip, __u64 bytes)
{
	struct ep_stats *s = bpf_map_lookup_elem(&stats_ep6, pod_ip);

	if (s) {
		s->tx_bytes += bytes;
		s->tx_pkts++;
	} else {
		struct ep_stats init = { .tx_bytes = bytes, .tx_pkts = 1 };

		bpf_map_update_elem(&stats_ep6, pod_ip, &init, BPF_ANY);
	}
}

/* ---- connect-time service LB ------------------------------------------- */
/* Return 1 = allow the connect (rewritten or not our VIP), 0 = EPERM. A VIP
 * with no backends refuses at connect(), never a black-hole timeout. */

SEC("cgroup/connect4")
int kanea_connect4(struct bpf_sock_addr *ctx)
{
	if (ctx->type != SOCK_STREAM)
		return 1;

	struct svc_key key = {
		.vip = ctx->user_ip4,
		/* user_port: network-ordered port in the low 16 bits */
		.port = (__be16)(ctx->user_port & 0xffff),
		.proto = IPPROTO_TCP,
		.pad = 0,
	};
	struct svc_val *svc = bpf_map_lookup_elem(&svc_v4, &key);

	if (!svc)
		return 1; /* not a VIP: plain connect */

	__u32 count = svc->count;

	if (count == 0) {
		count_drop(ctx->user_ip4, DROP_NO_BACKEND);
		return 0;
	}

	struct backend_key bkey = {
		.svc_id = svc->svc_id,
		.index = (__u16)(bpf_get_prandom_u32() % count),
		.gen = svc->gen,
	};
	struct backend_val *backend = bpf_map_lookup_elem(&svc_backends, &bkey);

	/* A miss here can only happen on a bug (a torn generation flip).
	 * Fail closed. */
	if (!backend)
		return 0;

	ctx->user_ip4 = backend->ip;
	ctx->user_port = (__u32)backend->port;

	count_connect(bkey.svc_id);
	return 1;
}

/* connect6 exists for two reasons, and the second is not obvious: native v6
 * VIPs, and v4-mapped destinations (::ffff:a.b.c.d); a dual-stack client
 * dialling a v4 VIP through an AF_INET6 socket bypasses the connect4 hook
 * entirely and would meet the blackhole route (v1.41). */
SEC("cgroup/connect6")
int kanea_connect6(struct bpf_sock_addr *ctx)
{
	if (ctx->type != SOCK_STREAM)
		return 1;

	if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
	    ctx->user_ip6[2] == __bpf_htonl(0x0000ffff)) {
		/* v4-mapped: the v4 service table decides, and only word 3 is
		 * rewritten so the socket stays v4-mapped. */
		struct svc_key key = {
			.vip = ctx->user_ip6[3],
			.port = (__be16)(ctx->user_port & 0xffff),
			.proto = IPPROTO_TCP,
			.pad = 0,
		};
		struct svc_val *svc = bpf_map_lookup_elem(&svc_v4, &key);

		if (!svc)
			return 1;

		__u32 count = svc->count;

		if (count == 0) {
			count_drop(ctx->user_ip6[3], DROP_NO_BACKEND);
			return 0;
		}

		struct backend_key bkey = {
			.svc_id = svc->svc_id,
			.index = (__u16)(bpf_get_prandom_u32() % count),
			.gen = svc->gen,
		};
		struct backend_val *backend =
			bpf_map_lookup_elem(&svc_backends, &bkey);

		if (!backend)
			return 0;

		ctx->user_ip6[3] = backend->ip;
		ctx->user_port = (__u32)backend->port;

		count_connect(bkey.svc_id);
		return 1;
	}

	struct svc_key6 key = {
		.port = (__be16)(ctx->user_port & 0xffff),
		.proto = IPPROTO_TCP,
		.pad = 0,
	};

	key.vip[0] = ctx->user_ip6[0];
	key.vip[1] = ctx->user_ip6[1];
	key.vip[2] = ctx->user_ip6[2];
	key.vip[3] = ctx->user_ip6[3];

	struct svc_val *svc = bpf_map_lookup_elem(&svc_v6, &key);

	if (!svc)
		return 1; /* not a VIP: plain connect */

	__u32 count = svc->count;

	if (count == 0) {
		struct in6_addr dst;

		dst.s6_addr32[0] = ctx->user_ip6[0];
		dst.s6_addr32[1] = ctx->user_ip6[1];
		dst.s6_addr32[2] = ctx->user_ip6[2];
		dst.s6_addr32[3] = ctx->user_ip6[3];
		count_drop6(&dst, DROP_NO_BACKEND);
		return 0;
	}

	struct backend_key bkey = {
		.svc_id = svc->svc_id,
		.index = (__u16)(bpf_get_prandom_u32() % count),
		.gen = svc->gen,
	};
	struct backend_val6 *backend = bpf_map_lookup_elem(&svc_backends6, &bkey);

	/* A miss here can only happen on a bug (a torn generation flip).
	 * Fail closed. */
	if (!backend)
		return 0;

	ctx->user_ip6[0] = backend->ip[0];
	ctx->user_ip6[1] = backend->ip[1];
	ctx->user_ip6[2] = backend->ip[2];
	ctx->user_ip6[3] = backend->ip[3];
	ctx->user_port = (__u32)backend->port;

	count_connect(bkey.svc_id);
	return 1;
}

/* ---- policy: veth egress toward the alloc ------------------------------ */

/* v6_enabled: config6's mask doubles as the enable switch. An unwritten
 * ARRAY entry is all-zero, so a node whose kanead never configured v6 reads
 * disabled, and the tc programs then drop ETH_P_IPV6 outright, closing the
 * unpoliced side channel the pre-v1.41 pass-through left open. */
static __always_inline int v6_enabled(void)
{
	__u32 zero = 0;
	struct dp_config6 *cfg = bpf_map_lookup_elem(&config6, &zero);

	if (!cfg)
		return 0;
	return (cfg->mask[0] | cfg->mask[1] | cfg->mask[2] | cfg->mask[3]) != 0;
}

/* The v6 half of kanea_to_container. Same shape as the v4 policy: dst then
 * src identity, host flag / same project / allow edge, SYN gate. The one
 * v6-specific restriction is deliberate: the TCP header is read only when
 * it sits directly behind the fixed 40-byte v6 header; no extension-header
 * walk. Both endpoints are Linux stacks kanead configured, extension
 * headers do not legitimately occur there, and a nexthdr this does not
 * recognise falls through to the deny-closed branch (PRD v1.41). */
static __always_inline int to_container_v6(struct __sk_buff *skb, void *data,
					   void *data_end)
{
	struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);

	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_SHOT; /* claimed IPv6, truncated: fail closed */

	if (!v6_enabled()) {
		count_drop6(&ip6->daddr, DROP_POLICY);
		return TC_ACT_SHOT;
	}

	struct identity *dst = bpf_map_lookup_elem(&identity_v6, &ip6->daddr);

	if (!dst) {
		count_drop6(&ip6->daddr, DROP_POLICY);
		return TC_ACT_SHOT;
	}

	struct identity *src = bpf_map_lookup_elem(&identity_v6, &ip6->saddr);

	if (!src) {
		/* The v4 rule's twin (v1.65): a source outside cluster_v6 has no
		 * identity by construction and passes; inside it, fail closed.
		 * Allocs have no v6 default route (no NAT66), so this is LAN v6
		 * an operator routed, not internet return traffic: the same
		 * grant either way. */
		__u32 czero = 0;
		struct dp_cidr6 *cluster =
			bpf_map_lookup_elem(&cluster_v6, &czero);

		if (cluster &&
		    (cluster->mask[0] | cluster->mask[1] | cluster->mask[2] |
		     cluster->mask[3]) &&
		    ((ip6->saddr.s6_addr32[0] & cluster->mask[0]) !=
			     cluster->net[0] ||
		     (ip6->saddr.s6_addr32[1] & cluster->mask[1]) !=
			     cluster->net[1] ||
		     (ip6->saddr.s6_addr32[2] & cluster->mask[2]) !=
			     cluster->net[2] ||
		     (ip6->saddr.s6_addr32[3] & cluster->mask[3]) !=
			     cluster->net[3]))
			goto pass;
		count_drop6(&ip6->daddr, DROP_POLICY);
		return TC_ACT_SHOT;
	}

	if (src->flags & IDENTITY_FLAG_HOST)
		goto pass;
	if (src->project_id == dst->project_id)
		goto pass;

	struct allow_key akey = {
		.dst_service_id = dst->service_id,
		.src_service_id = src->service_id,
	};

	if (bpf_map_lookup_elem(&allow_v4, &akey))
		goto pass;

	if (ip6->nexthdr == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)(ip6 + 1);

		if ((void *)(tcp + 1) > data_end) {
			count_drop6(&ip6->daddr, DROP_POLICY);
			return TC_ACT_SHOT;
		}
		if (!(tcp->syn && !tcp->ack))
			goto pass;
	}

	/* A cross-project SYN with no allow rule, and any nexthdr that is
	 * not plain TCP (ICMPv6, an extension header): with static neighbors
	 * and NODAD there is no ND to carry, host-originated ICMPv6 already
	 * passed on the host flag, and cross-project ICMPv6 is denied like
	 * its v4 sibling. */
	count_drop6(&ip6->daddr, DROP_POLICY);
	return TC_ACT_SHOT;

pass:
	count_rx6(&ip6->daddr, skb->len);
	return TC_ACT_OK;
}

SEC("tc")
int kanea_to_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK; /* not even an ethernet frame */
	if (eth->h_proto == __bpf_htons(ETH_P_IPV6))
		return to_container_v6(skb, data, data_end);
	if (eth->h_proto == __bpf_htons(ETH_P_IP))
		goto ipv4;
	/* K-31: exactly IPv4, IPv6 and ARP cross a Kanea veth. Anything else -
	 * a VLAN/QinQ frame is the case that matters - would bypass every L3
	 * check below, so it is dropped and counted rather than passed. */
	if (eth->h_proto == __bpf_htons(ETH_P_ARP))
		return TC_ACT_OK;
	count_drop(0, DROP_ETHERTYPE);
	return TC_ACT_SHOT;

ipv4:
	; /* a label precedes no declaration (pre-C23) */

	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT; /* claimed IPv4, truncated: fail closed */

	/* On this veth's egress the destination IS our pod. An identity miss
	 * means the entry is gone mid-teardown: drop is the fail-closed
	 * answer, and it is what makes the attach order deny-closed by
	 * construction. */
	struct identity *dst = bpf_map_lookup_elem(&identity_v4, &ip->daddr);

	if (!dst) {
		count_drop(ip->daddr, DROP_POLICY);
		return TC_ACT_SHOT;
	}

	struct identity *src = bpf_map_lookup_elem(&identity_v4, &ip->saddr);

	if (!src) {
		/* No identity: a cluster-internal source is an alloc mid-teardown;
		 * fail closed, exactly the deny the attach order relies on. One
		 * from OUTSIDE the cluster is the world answering a connection an
		 * alloc opened (conntrack un-NATed it on the way in) and passes:
		 * kanead's allocator writes every identity, so an external address
		 * can never have one, and dropping it made egress send-only
		 * (v1.65). The mask guard keeps the unwritten map (all-zero, an
		 * ARRAY's birth state) dropping, never open. */
		__u32 czero = 0;
		struct dp_cidr *cluster =
			bpf_map_lookup_elem(&cluster_v4, &czero);

		if (cluster && cluster->mask &&
		    (ip->saddr & cluster->mask) != cluster->net)
			goto pass;
		count_drop(ip->daddr, DROP_POLICY);
		return TC_ACT_SHOT;
	}

	if (src->flags & IDENTITY_FLAG_HOST)
		goto pass;
	if (src->project_id == dst->project_id)
		goto pass;

	struct allow_key akey = {
		.dst_service_id = dst->service_id,
		.src_service_id = src->service_id,
	};

	if (bpf_map_lookup_elem(&allow_v4, &akey))
		goto pass;

	/* SYN-gated stateless policy: only connection *attempts* are checked.
	 * Non-SYN TCP passes so cross-project allow_from replies flow without
	 * a conntrack; an in-node ACK probe is stopped by the stack's RST. */
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = data + sizeof(struct ethhdr) +
				     (__u32)ip->ihl * 4;

		if (ip->ihl < 5 || (void *)(tcp + 1) > data_end) {
			count_drop(ip->daddr, DROP_POLICY);
			return TC_ACT_SHOT;
		}
		if (!(tcp->syn && !tcp->ack))
			goto pass;
	}

	/* A cross-project SYN with no allow rule, and non-TCP (UDP/ICMP)
	 * that reached here: DNS goes to kanea0, not pod-to-pod, and
	 * cross-project ICMP is denied (same-project/host/allowed ICMP
	 * already passed above). */
	count_drop(ip->daddr, DROP_POLICY);
	return TC_ACT_SHOT;

pass:
	count_rx(ip->daddr, skb->len);
	return TC_ACT_OK;
}

/* ---- egress guard: veth ingress from the alloc ------------------------- */

/* The v6 half of kanea_from_container: link-local and multicast never leave
 * an alloc (fe80::/10, ff00::/8; MLD reports, stray RS/NS), the AWS
 * metadata ULA fd00:ec2::254 is §14 A10's v6 half, and a service-CIDR6
 * destination that escaped connect-time rewrite is refused like its v4
 * sibling. */
static __always_inline int from_container_v6(struct __sk_buff *skb, void *data,
					     void *data_end)
{
	struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);

	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_SHOT;

	if (!v6_enabled()) {
		count_drop6(&ip6->daddr, DROP_POLICY);
		return TC_ACT_SHOT;
	}

	/* fe80::/10 link-local and ff00::/8 multicast: with NODAD, static
	 * neighbors and no autoconf nothing legitimate uses either, and the
	 * kernel's own MLD chatter should die here quietly rather than roam. */
	if ((ip6->daddr.s6_addr32[0] & __bpf_htonl(0xFFC00000)) ==
	    __bpf_htonl(0xFE800000)) {
		count_drop6(&ip6->daddr, DROP_LINK_LOCAL);
		return TC_ACT_SHOT;
	}
	if ((ip6->daddr.s6_addr32[0] & __bpf_htonl(0xFF000000)) ==
	    __bpf_htonl(0xFF000000)) {
		count_drop6(&ip6->daddr, DROP_LINK_LOCAL);
		return TC_ACT_SHOT;
	}

	/* fd00:ec2::254: the AWS IMDS ULA (§14 A10). Exact match: it is one
	 * address, not a range. */
	if (ip6->daddr.s6_addr32[0] == __bpf_htonl(0xFD000EC2) &&
	    ip6->daddr.s6_addr32[1] == 0 && ip6->daddr.s6_addr32[2] == 0 &&
	    ip6->daddr.s6_addr32[3] == __bpf_htonl(0x00000254)) {
		count_drop6(&ip6->daddr, DROP_METADATA);
		return TC_ACT_SHOT;
	}

	/* NAT64-wrapped metadata (64:ff9b::/96, K-32): the embedded v4 address
	 * gets the v4 rules, or the v6 egress would pass what the v4 one drops
	 * - the same decode the notification egress guard does (§3.9). */
	if (ip6->daddr.s6_addr32[0] == __bpf_htonl(0x0064FF9B) &&
	    ip6->daddr.s6_addr32[1] == 0 && ip6->daddr.s6_addr32[2] == 0) {
		__be32 v4 = ip6->daddr.s6_addr32[3];

		if ((v4 & __bpf_htonl(0xFFFF0000)) == __bpf_htonl(0xA9FE0000) ||
		    v4 == __bpf_htonl(0x646464C8)) {
			count_drop6(&ip6->daddr, DROP_METADATA);
			return TC_ACT_SHOT;
		}
	}

	/* Anti-spoof, the v4 rule's twin (K-09, v1.77): exact source binding
	 * per veth, fail-closed on a miss. */
	{
		__u32 ifindex = skb->ingress_ifindex;
		struct in6_addr *assigned =
			bpf_map_lookup_elem(&veth_src6, &ifindex);

		if (!assigned ||
		    assigned->s6_addr32[0] != ip6->saddr.s6_addr32[0] ||
		    assigned->s6_addr32[1] != ip6->saddr.s6_addr32[1] ||
		    assigned->s6_addr32[2] != ip6->saddr.s6_addr32[2] ||
		    assigned->s6_addr32[3] != ip6->saddr.s6_addr32[3]) {
			count_drop6(&ip6->daddr, DROP_SPOOF);
			return TC_ACT_SHOT;
		}
	}

	__u32 zero = 0;
	struct dp_config6 *cfg = bpf_map_lookup_elem(&config6, &zero);

	/* v6_enabled() above proved the mask is non-zero; the re-lookup is for
	 * the verifier, which cannot carry the pointer across the helper. */
	if (cfg &&
	    (ip6->daddr.s6_addr32[0] & cfg->mask[0]) == cfg->net[0] &&
	    (ip6->daddr.s6_addr32[1] & cfg->mask[1]) == cfg->net[1] &&
	    (ip6->daddr.s6_addr32[2] & cfg->mask[2]) == cfg->net[2] &&
	    (ip6->daddr.s6_addr32[3] & cfg->mask[3]) == cfg->net[3]) {
		count_drop6(&ip6->daddr, DROP_VIP_LEAK);
		return TC_ACT_SHOT;
	}

	count_tx6(&ip6->saddr, skb->len);
	return TC_ACT_OK;
}

SEC("tc")
int kanea_from_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto == __bpf_htons(ETH_P_IPV6))
		return from_container_v6(skb, data, data_end);
	if (eth->h_proto == __bpf_htons(ETH_P_IP))
		goto ipv4;
	/* K-31: exactly IPv4, IPv6 and ARP cross a Kanea veth. Anything else -
	 * a VLAN/QinQ frame is the case that matters - would bypass every L3
	 * check below, so it is dropped and counted rather than passed. */
	if (eth->h_proto == __bpf_htons(ETH_P_ARP))
		return TC_ACT_OK;
	count_drop(0, DROP_ETHERTYPE);
	return TC_ACT_SHOT;

ipv4:
	; /* a label precedes no declaration (pre-C23) */

	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;

	/* 169.254.0.0/16: the metadata range never leaves an alloc (§14 A10). */
	if ((ip->daddr & __bpf_htonl(0xFFFF0000)) == __bpf_htonl(0xA9FE0000)) {
		count_drop(ip->daddr, DROP_METADATA);
		return TC_ACT_SHOT;
	}
	/* 100.100.100.200/32: Alibaba's metadata address, the same class
	 * (K-32). */
	if (ip->daddr == __bpf_htonl(0x646464C8)) {
		count_drop(ip->daddr, DROP_METADATA);
		return TC_ACT_SHOT;
	}

	/* 224.0.0.0/4 multicast and the limited broadcast: host-side LLMNR/mDNS
	 * listeners are not for allocs (K-30); the v6 program has always dropped
	 * its equivalents. */
	if ((ip->daddr & __bpf_htonl(0xF0000000)) == __bpf_htonl(0xE0000000) ||
	    ip->daddr == __bpf_htonl(0xFFFFFFFF)) {
		count_drop(ip->daddr, DROP_MULTICAST);
		return TC_ACT_SHOT;
	}

	/* Anti-spoof (K-09, v1.77): the source must be exactly the address
	 * kanead assigned this veth, so the identity a destination's policy
	 * evaluates cannot be forged from inside the alloc. A missing entry
	 * fails closed, like an identity miss; Init populates entries for
	 * pre-upgrade veths before the programs reach them, and plumb writes
	 * before link-up. The cluster-CIDR source check this replaces only
	 * ever bounded the forgery to inside the cluster. */
	{
		__u32 ifindex = skb->ingress_ifindex;
		__be32 *assigned = bpf_map_lookup_elem(&veth_src, &ifindex);

		if (!assigned || *assigned != ip->saddr) {
			count_drop(ip->daddr, DROP_SPOOF);
			return TC_ACT_SHOT;
		}
	}

	/* A packet addressed to the service CIDR escaped connect-time rewrite
	 * (raw sockets, UDP to a VIP): refuse it here rather than let it
	 * black-hole. The mask guard keeps an unwritten config entry (an
	 * ARRAY map is zero-filled) from reading as "0.0.0.0/0 is the
	 * service CIDR" and dropping everything. */
	__u32 zero = 0;
	struct dp_config *cfg = bpf_map_lookup_elem(&config, &zero);

	if (cfg && cfg->service_cidr_mask &&
	    (ip->daddr & cfg->service_cidr_mask) == cfg->service_cidr_net) {
		count_drop(ip->daddr, DROP_VIP_LEAK);
		return TC_ACT_SHOT;
	}

	count_tx(ip->saddr, skb->len);
	return TC_ACT_OK;
}
