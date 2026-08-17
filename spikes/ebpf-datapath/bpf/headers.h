/* SPDX-License-Identifier: GPL-2.0-only OR MIT */
/*
 * headers.h; self-contained minimal UAPI definitions for the spike's BPF
 * programs. Deliberately no vmlinux.h and no CO-RE: the structs below mirror
 * the *stable UAPI* context layouts (include/uapi/linux/bpf.h) that the
 * verifier's context rewriting is keyed on, so exact field offsets matter
 * and must not be "cleaned up".
 *
 * Little-endian targets only (bpfel): both target nodes (Debian 11 amd64,
 * current kernel amd64/arm64) are LE, and build.sh compiles with -target bpf
 * on the node itself.
 */
#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;
typedef __u32 __be32;

/* byte order (bpfel only, see header comment) */
#define bpf_htons(x) ((__be16)__builtin_bswap16((__u16)(x)))
#define bpf_htonl(x) ((__be32)__builtin_bswap32((__u32)(x)))

#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))

/* BTF-style map definition macros (the bpf_helpers.h subset we use) */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* enum bpf_map_type (subset) */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_PERCPU_ARRAY 6

/* map update flags */
#define BPF_ANY 0
#define BPF_NOEXIST 1

/* LIBBPF_PIN_BY_NAME */
#define PIN_BY_NAME 1

/* helpers: enum bpf_func_id values are UAPI-stable */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
				   __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u32 (*bpf_get_prandom_u32)(void) = (void *)7;

/* socket / protocol constants */
#define SOCK_STREAM 1
#define IPPROTO_TCP 6
#define ETH_P_IP 0x0800

/* tc verdicts */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/*
 * struct bpf_sock_addr: full UAPI layout as of the 5.10 floor. The `sk`
 * tail member is really __bpf_md_ptr(struct bpf_sock *, sk); we never touch
 * it, only its alignment matters for the fields before it (none follow).
 */
struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	__u64 sk __attribute__((aligned(8)));
};

/* struct __sk_buff: UAPI prefix; fields past data_end are unused here */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
};

/*
 * Packet headers; bitfield-free on purpose: bitfield layout differs by
 * endianness, so version/ihl and the TCP flags are read as raw bytes
 * instead, which is byte-order proof.
 */
struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
} __attribute__((packed));

struct iphdr {
	__u8 ver_ihl; /* version in the high nibble, ihl in the low one */
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__be32 saddr;
	__be32 daddr;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u8 doff_res; /* data offset in the high nibble */
	__u8 flags;    /* CWR ECE URG ACK PSH RST SYN FIN */
	__be16 window;
	__u16 check;
	__be16 urg_ptr;
};

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10
