/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * spike.c — the three datapath programs of Kanea's planned internal eBPF
 * datapath (the standalone-Cilium replacement), minimal but real:
 *
 *   P1 kanea_connect4       cgroup/connect4 at the root cgroup: service VIP
 *                           load balancing at connect(2) time (TCP only).
 *   P2 kanea_to_container   tc egress on the host-side veth (traffic INTO
 *                           the container): SYN-gated stateless policy.
 *   P3 kanea_from_container tc ingress on the host-side veth (traffic
 *                           LEAVING the container): link-local + service-CIDR
 *                           guard, per-endpoint tx accounting.
 *
 * kanea_connect4_proto is a compile/load probe, never attached in anger: it
 * reads ctx->protocol, and whether it verifies on the 5.10 floor is one of
 * the things the harness records (check 11).
 *
 * Throwaway M0-style validation code. Nothing here ships.
 */
#include "headers.h"

char _license[] SEC("license") = "Dual MIT/GPL";

/* ---- key/value layouts, mirrored byte-for-byte in maps.go ---- */

struct svc_key {
	__be32 ip;
	__be16 port; /* network byte order, like bpf_sock_addr.user_port */
	__u8 proto;
	__u8 pad;
};

struct svc_val {
	__u16 svc_id;
	__u16 count;
	__u32 gen;
};

struct backend_key {
	__u16 svc_id;
	__u16 index;
	__u32 gen;
};

struct backend_val {
	__be32 ip;
	__be16 port;
	__u16 pad;
};

struct identity_val {
	__u32 project_id;
	__u32 service_id;
	__u32 flags;
};

struct allow_key {
	__u32 dst_service_id;
	__u32 src_service_id;
};

struct ep_stats {
	__u64 pkts;
	__u64 bytes;
};

#define FLAG_HOST 0x1

/* stats_drops indices */
#define DROP_ID_MISS 0
#define DROP_POLICY 1
#define DROP_LINKLOCAL 2
#define DROP_SVC_CIDR 3

/* ---- maps, all pinned by name under the spike's own pin root ---- */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct svc_key);
	__type(value, struct svc_val);
	__uint(pinning, PIN_BY_NAME);
} svc_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct backend_key);
	__type(value, struct backend_val);
	__uint(pinning, PIN_BY_NAME);
} svc_backends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __be32);
	__type(value, struct identity_val);
	__uint(pinning, PIN_BY_NAME);
} identity_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct allow_key);
	__type(value, __u8);
	__uint(pinning, PIN_BY_NAME);
} allow_v4 SEC(".maps");

/* per-cpu: svc_id -> connects through the LB */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, PIN_BY_NAME);
} stats_svc SEC(".maps");

/* per-cpu: DROP_* reason -> count */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 8);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, PIN_BY_NAME);
} stats_drops SEC(".maps");

/* per-cpu: endpoint source ip -> tx pkts/bytes */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 4096);
	__type(key, __be32);
	__type(value, struct ep_stats);
	__uint(pinning, PIN_BY_NAME);
} stats_ep SEC(".maps");

static __always_inline void count_drop(__u32 reason)
{
	__u64 *v = bpf_map_lookup_elem(&stats_drops, &reason);

	if (v)
		(*v)++;
}

/* ================= P1: connect-time service load balancing ============= */

static __always_inline int lb4(struct bpf_sock_addr *ctx)
{
	/* user_port is a u32 holding the port in network byte order; the
	 * truncating cast keeps exactly those two bytes on bpfel. */
	struct svc_key k = {
		.ip = ctx->user_ip4,
		.port = (__be16)ctx->user_port,
		.proto = IPPROTO_TCP,
	};
	struct svc_val *svc = bpf_map_lookup_elem(&svc_v4, &k);

	if (!svc)
		return 1; /* not a VIP: allow the connect untouched */
	if (!svc->count)
		return 0; /* zero backends: refuse -> connect(2) fails EPERM */

	struct backend_key bk = {
		.svc_id = svc->svc_id,
		.index = (__u16)(bpf_get_prandom_u32() % svc->count),
		.gen = svc->gen,
	};
	struct backend_val *b = bpf_map_lookup_elem(&svc_backends, &bk);

	if (!b)
		return 0; /* torn/missing backend set: refuse, never misroute */

	ctx->user_ip4 = b->ip;
	ctx->user_port = (__u32)b->port;

	__u32 idx = svc->svc_id;
	__u64 *n = bpf_map_lookup_elem(&stats_svc, &idx);

	if (n)
		(*n)++;
	return 1;
}

SEC("cgroup/connect4")
int kanea_connect4(struct bpf_sock_addr *ctx)
{
	/* TCP only. ctx->type has been readable since bpf_sock_addr exists;
	 * whether ctx->protocol also is at the 5.10 floor is what the _proto
	 * variant below probes. SOCK_STREAM over inet is TCP (SCTP has no
	 * IPPROTO_TCP socket type confusion worth carrying in a spike). */
	if (ctx->type != SOCK_STREAM)
		return 1;
	return lb4(ctx);
}

/* Load probe for check 11 — identical, but gates on ctx->protocol too. */
SEC("cgroup/connect4")
int kanea_connect4_proto(struct bpf_sock_addr *ctx)
{
	if (ctx->type != SOCK_STREAM || ctx->protocol != IPPROTO_TCP)
		return 1;
	return lb4(ctx);
}

/* ============ P2: tc egress on the host veth = INTO the container ====== */

SEC("tc")
int kanea_to_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK; /* ARP etc. are not this program's job */

	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	struct identity_val *dst = bpf_map_lookup_elem(&identity_v4, &ip->daddr);

	if (!dst)
		return TC_ACT_OK; /* no programmed identity behind this veth */

	struct identity_val *src = bpf_map_lookup_elem(&identity_v4, &ip->saddr);

	if (!src) {
		count_drop(DROP_ID_MISS);
		return TC_ACT_SHOT; /* unknown source: default deny */
	}
	if (src->flags & FLAG_HOST)
		return TC_ACT_OK;
	if (src->project_id == dst->project_id)
		return TC_ACT_OK;

	struct allow_key ak = {
		.dst_service_id = dst->service_id,
		.src_service_id = src->service_id,
	};

	if (bpf_map_lookup_elem(&allow_v4, &ak))
		return TC_ACT_OK;

	if (ip->protocol == IPPROTO_TCP) {
		__u32 ihl = ((__u32)ip->ver_ihl & 0x0f) * 4;
		struct tcphdr *tcp = (void *)ip + ihl;

		if ((void *)(tcp + 1) > data_end) {
			count_drop(DROP_POLICY);
			return TC_ACT_SHOT;
		}
		/* SYN-gated stateless policy: only a connection attempt
		 * (SYN, no ACK) is policed; everything else is reply or
		 * established traffic of a flow whose own SYN already passed
		 * the gate in the other direction. */
		if (!(tcp->flags & TCP_FLAG_SYN) || (tcp->flags & TCP_FLAG_ACK))
			return TC_ACT_OK;
	}
	count_drop(DROP_POLICY);
	return TC_ACT_SHOT;
}

/* ========== P3: tc ingress on the host veth = LEAVING the container ==== */

SEC("tc")
int kanea_from_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);

	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	/* 169.254.0.0/16 — the metadata-service class of destination */
	if ((ip->daddr & bpf_htonl(0xffff0000)) == bpf_htonl(0xa9fe0000)) {
		count_drop(DROP_LINKLOCAL);
		return TC_ACT_SHOT;
	}
	/* 10.201.0.0/16 — a VIP is a connect-time concept; a raw packet to
	 * one on the wire is a bypass attempt, not a service connection */
	if ((ip->daddr & bpf_htonl(0xffff0000)) == bpf_htonl(0x0ac90000)) {
		count_drop(DROP_SVC_CIDR);
		return TC_ACT_SHOT;
	}

	struct ep_stats *s = bpf_map_lookup_elem(&stats_ep, &ip->saddr);

	if (!s) {
		struct ep_stats zero = {};

		bpf_map_update_elem(&stats_ep, &ip->saddr, &zero, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&stats_ep, &ip->saddr);
	}
	if (s) {
		s->pkts++;
		s->bytes += skb->len;
	}
	return TC_ACT_OK;
}
