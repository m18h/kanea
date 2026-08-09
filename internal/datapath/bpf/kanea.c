// SPDX-License-Identifier: (GPL-2.0-only OR MIT)

//go:build ignore
// (The constraint above keeps the Go toolchain from treating this file as
// a cgo input: go/build reads build constraints in .c files too.)

/*
 * kanea.c — the Kanea datapath (PRD v1.36 §5.2.5): three programs, one
 * compile unit.
 *
 *   kanea_connect4       cgroup/connect4  connect-time service LB
 *   kanea_to_container   tc               policy on the veth toward an alloc
 *   kanea_from_container tc               egress guard on the veth from an alloc
 *
 * IP is identity: kanead allocates every address and writes identity_v4
 * itself, so there is no identity protocol and no settle window. Policy is
 * SYN-gated and stateless — non-SYN TCP passes so cross-project allow_from
 * replies flow without a conntrack. Established connections never consult
 * a map; backend sets change by generation flip (see dpmap.FlipPlan).
 *
 * No bpf_trace_printk anywhere: a drop is counted in stats_drops, never
 * logged from the datapath.
 */

#include "headers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* ---- drop reasons (mirrored by dpmap.DropReason*) ---------------------- */

#define DROP_POLICY 1
#define DROP_METADATA 2
#define DROP_NO_BACKEND 3
#define DROP_VIP_LEAK 4

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

		bpf_map_update_elem(&stats_drops, &key, &one, BPF_ANY);
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
		return 1; /* not a VIP — plain connect */

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

/* ---- policy: veth egress toward the alloc ------------------------------ */

SEC("tc")
int kanea_to_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK; /* not even an ethernet frame */
	if (eth->h_proto != __bpf_htons(ETH_P_IP))
		return TC_ACT_OK; /* non-IPv4 (ARP, IPv6 ND) passes */

	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT; /* claimed IPv4, truncated: fail closed */

	/* On this veth's egress the destination IS our pod. An identity miss
	 * means the entry is gone mid-teardown — drop is the fail-closed
	 * answer, and it is what makes the attach order deny-closed by
	 * construction. */
	struct identity *dst = bpf_map_lookup_elem(&identity_v4, &ip->daddr);

	if (!dst) {
		count_drop(ip->daddr, DROP_POLICY);
		return TC_ACT_SHOT;
	}

	struct identity *src = bpf_map_lookup_elem(&identity_v4, &ip->saddr);

	if (!src) {
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

	/* A cross-project SYN with no allow rule — and non-TCP (UDP/ICMP)
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

SEC("tc")
int kanea_from_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != __bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_SHOT;

	/* 169.254.0.0/16: the metadata range never leaves an alloc (§14 A10). */
	if ((ip->daddr & __bpf_htonl(0xFFFF0000)) == __bpf_htonl(0xA9FE0000)) {
		count_drop(ip->daddr, DROP_METADATA);
		return TC_ACT_SHOT;
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
