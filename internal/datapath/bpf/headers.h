// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * headers.h — the minimal, self-contained UAPI surface the Kanea datapath
 * programs compile against.
 *
 * Deliberately NOT <linux/bpf.h>, NOT vmlinux.h, NOT CO-RE (PRD v1.36
 * §5.2.5): the programs read only stable UAPI context layouts, so the
 * target node needs no BTF and the build needs no kernel headers. Every
 * definition here mirrors the kernel UAPI byte-for-byte; the context
 * structs are truncated prefixes — the verifier checks field *offsets* in
 * the compiled instructions, not our struct declarations, so a prefix that
 * covers every field we touch is exact.
 */
#pragma once

/* ---- fixed-width types (matching <linux/types.h>) ---------------------- */

typedef signed char __s8;
typedef unsigned char __u8;
typedef signed short __s16;
typedef unsigned short __u16;
typedef signed int __s32;
typedef unsigned int __u32;
typedef signed long long __s64;
typedef unsigned long long __u64;

/* Annotations only: a __be* field holds network byte order regardless of
 * the host. The compiler does not enforce this — the names document it. */
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u16 __sum16;

/* ---- section / BTF map-definition macros (matching bpf_helpers.h) ------ */

#define SEC(name) __attribute__((section(name), used))

#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* ---- constants --------------------------------------------------------- */

/* enum bpf_map_type */
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_HASH 5

/* flags for bpf_map_update_elem() */
#define BPF_ANY 0

/* <linux/if_ether.h> */
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

/* <linux/in.h> */
#define IPPROTO_TCP 6

/* <linux/net.h> enum sock_type */
#define SOCK_STREAM 1

/* <linux/pkt_cls.h> */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/* ---- helper functions, by UAPI helper number --------------------------- */

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
				   const void *value, __u64 flags) = (void *)2;
static __u32 (*bpf_get_prandom_u32)(void) = (void *)7;

/* ---- byte-order helpers (constant-folding, as in bpf_endian.h) --------- */

#define ___bpf_swab16(x)                                                       \
	((__u16)((((__u16)(x) & (__u16)0x00ffU) << 8) |                        \
		 (((__u16)(x) & (__u16)0xff00U) >> 8)))

#define ___bpf_swab32(x)                                                       \
	((__u32)((((__u32)(x) & (__u32)0x000000ffUL) << 24) |                  \
		 (((__u32)(x) & (__u32)0x0000ff00UL) << 8) |                   \
		 (((__u32)(x) & (__u32)0x00ff0000UL) >> 8) |                   \
		 (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#define __bpf_htons(x)                                                         \
	(__builtin_constant_p(x) ? ___bpf_swab16(x) : __builtin_bswap16(x))
#define __bpf_ntohs(x)                                                         \
	(__builtin_constant_p(x) ? ___bpf_swab16(x) : __builtin_bswap16(x))
#define __bpf_htonl(x)                                                         \
	(__builtin_constant_p(x) ? ___bpf_swab32(x) : __builtin_bswap32(x))
#define __bpf_ntohl(x)                                                         \
	(__builtin_constant_p(x) ? ___bpf_swab32(x) : __builtin_bswap32(x))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD
#define __bpf_htons(x) (x)
#define __bpf_ntohs(x) (x)
#define __bpf_htonl(x) (x)
#define __bpf_ntohl(x) (x)
#else
#error "unknown target byte order"
#endif

/* ---- BPF program context types (UAPI <linux/bpf.h>) -------------------- */

/* Truncated prefix of struct __sk_buff: everything up to and including
 * data_end (offset 80). The programs touch len, protocol, data, data_end. */
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
};

/* Truncated prefix of struct bpf_sock_addr: everything up to and including
 * protocol (offset 36). user_port holds the port network-ordered in the
 * low 16 bits of a __u32; 4-byte reads and writes work on every kernel we
 * support (≥ 5.10). */
struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
};

/* ---- packet header layouts (UAPI <linux/if_ether.h>, ip.h, tcp.h) ------ */

struct ethhdr {
	__u8 h_dest[ETH_ALEN];
	__u8 h_source[ETH_ALEN];
	__be16 h_proto;
} __attribute__((packed));

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 ihl : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 version : 4, ihl : 4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

/* <linux/in6.h> struct in6_addr, as the one member of its union we read.
 * The UAPI type is a union of u8[16]/u16[8]/u32[4] views over the same 16
 * bytes; declaring only the 32-bit view keeps the layout identical and the
 * map-key size (16) exact. */
struct in6_addr {
	__be32 s6_addr32[4];
};

/* <linux/ipv6.h> struct ipv6hdr — fixed 40 bytes, no options inside the
 * header itself. Extension headers follow it and are deliberately not
 * parsed (PRD v1.41): both endpoints are Linux stacks kanead configured,
 * and a packet whose nexthdr is not TCP falls through to the deny-closed
 * branch of the policy program. */
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 priority : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8 version : 4, priority : 4;
#endif
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1,
		urg : 1, ece : 1, cwr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1,
		rst : 1, syn : 1, fin : 1;
#endif
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};
