// Package dpmap is the userspace half of the datapath's map contract
// (PRD v1.36 §5.2.5): Go mirrors of every key and value layout declared in
// internal/datapath/bpf/kanea.c, plus the reference backend selection and
// the generation-flip plan the linux map writer executes.
//
// The package is pure Go (no build tags, no cilium/ebpf import) so the
// layouts and the flip's atomicity properties are testable on any platform.
//
// Byte layout: a BPF map key or value is raw bytes; the C structs use
// host-endian __u16/__u32/__u64 fields and network-order __be16/__be32
// fields. Marshal/Unmarshal here encode host-endian fields with
// binary.LittleEndian explicitly: matching the bpfel object, which is the
// one a v1 node loads (amd64 and arm64 are both little-endian; big-endian
// nodes, the bpfeb object, are out of scope for v1). IPs and ports declared
// __be* are encoded in network byte order: an IP travels as its [4]byte
// wire form unchanged, a port is written big-endian.
package dpmap

import (
	"encoding/binary"
	"fmt"
)

// Drop reasons, mirroring the DROP_* constants in kanea.c. They key
// stats_drops together with the destination address.
const (
	DropReasonPolicy    uint8 = 1 // policy denied a connection attempt
	DropReasonMetadata  uint8 = 2 // 169.254.0.0/16 / fd00:ec2::254 egress (§14 A10)
	DropReasonNoBackend uint8 = 3 // a VIP with an empty backend set
	DropReasonVIPLeak   uint8 = 4 // service-CIDR traffic that escaped rewrite
	// DropReasonLinkLocal is v6-only (v1.41): fe80::/10 and ff00::/8 egress.
	// With NODAD, static neighbors and no autoconf nothing legitimate sends
	// either; the counter keeps the kernel's own MLD chatter visible.
	DropReasonLinkLocal uint8 = 5
	// DropReasonSpoof (v1.65): an alloc emitted a packet whose source is
	// not a cluster address. A forged external source would ride the
	// return-traffic pass in to_container straight past policy, so the
	// egress guard refuses it at the veth.
	DropReasonSpoof uint8 = 6
)

// IdentityFlagHost marks an address as the host's, not an alloc's
// (identity.flags bit 0 in kanea.c).
const IdentityFlagHost uint32 = 1

// Map names as they appear in the BPF object and under the pin root.
const (
	MapSvcV4       = "svc_v4"
	MapSvcBackends = "svc_backends"
	MapIdentityV4  = "identity_v4"
	MapAllowV4     = "allow_v4"
	MapStatsSvc    = "stats_svc"
	MapStatsEp     = "stats_ep"
	MapStatsDrops  = "stats_drops"
	MapConfig      = "config"

	// The v6 twins (v1.41): separate maps beside the v4 ones, never widened;
	// widening a pinned map's key changes its ABI and would wipe every node's
	// pins at upgrade. allow_v4 and stats_svc are id-keyed and shared; the
	// v4 name of the former is historical, not a family restriction.
	MapSvcV6        = "svc_v6"
	MapSvcBackends6 = "svc_backends6"
	MapIdentityV6   = "identity_v6"
	MapStatsEp6     = "stats_ep6"
	MapStatsDrops6  = "stats_drops6"
	MapConfig6      = "config6"

	// The cluster CIDR maps (v1.65): new maps beside config, never a widened
	// dp_config; the same ABI rule that kept the v6 maps separate. Their
	// all-zero birth state reads as "no cluster configured", which the
	// programs treat as the pre-v1.65 deny.
	MapClusterV4 = "cluster_v4"
	MapClusterV6 = "cluster_v6"
)

// PinRoot is where the datapath pins its maps, programs and links.
// Nothing under it is ever backed up: it is derived state, rebuilt from
// the Store (constraint #9).
const PinRoot = "/sys/fs/bpf/kanea"

// PinPath returns the bpffs pin path for a named map.
func PinPath(name string) string { return PinRoot + "/" + name }

// Encoded sizes in bytes, each pinned to the C sizeof by a test.
const (
	SvcKeySize      = 8
	SvcValSize      = 8
	BackendKeySize  = 8
	BackendValSize  = 8
	IdentitySize    = 12
	AllowKeySize    = 8
	DropKeySize     = 8
	EpStatsSize     = 32
	ConfigSize      = 8
	StatsSvcKeySize = 2 // __u16 svc_id
	StatsEpKeySize  = 4 // __be32 pod ip
	StatsValSize    = 8 // __u64 counter

	SvcKey6Size     = 20
	BackendVal6Size = 20
	DropKey6Size    = 20
	Config6Size     = 32
	StatsEp6KeySize = 16 // struct in6_addr pod ip; also identity_v6's key

	CIDRSize  = 8  // struct dp_cidr
	CIDR6Size = 32 // struct dp_cidr6
)

func checkLen(what string, b []byte, want int) error {
	if len(b) != want {
		return fmt.Errorf("dpmap: %s: got %d bytes, want %d", what, len(b), want)
	}
	return nil
}

// SvcKey is svc_v4's key: struct svc_key in kanea.c.
type SvcKey struct {
	VIP   [4]byte // network order, as on the wire
	Port  uint16  // host value here; encoded big-endian (__be16)
	Proto uint8   // IPPROTO_*; always TCP for v1 service ports
}

// Marshal encodes the key in the C struct's byte layout.
func (k SvcKey) Marshal() []byte {
	b := make([]byte, SvcKeySize)
	copy(b[0:4], k.VIP[:])
	binary.BigEndian.PutUint16(b[4:6], k.Port)
	b[6] = k.Proto
	// b[7] is explicit padding, always zero.
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (k *SvcKey) Unmarshal(b []byte) error {
	if err := checkLen("svc_key", b, SvcKeySize); err != nil {
		return err
	}
	copy(k.VIP[:], b[0:4])
	k.Port = binary.BigEndian.Uint16(b[4:6])
	k.Proto = b[6]
	return nil
}

// SvcVal is svc_v4's value: struct svc_val in kanea.c. Gen names the
// backend generation the entry commits; updating it is the atomic flip.
type SvcVal struct {
	SvcID uint16
	Count uint16
	Gen   uint32
}

// Marshal encodes the value in the C struct's byte layout.
func (v SvcVal) Marshal() []byte {
	b := make([]byte, SvcValSize)
	binary.LittleEndian.PutUint16(b[0:2], v.SvcID)
	binary.LittleEndian.PutUint16(b[2:4], v.Count)
	binary.LittleEndian.PutUint32(b[4:8], v.Gen)
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *SvcVal) Unmarshal(b []byte) error {
	if err := checkLen("svc_val", b, SvcValSize); err != nil {
		return err
	}
	v.SvcID = binary.LittleEndian.Uint16(b[0:2])
	v.Count = binary.LittleEndian.Uint16(b[2:4])
	v.Gen = binary.LittleEndian.Uint32(b[4:8])
	return nil
}

// BackendKey is svc_backends' key: struct backend_key in kanea.c.
type BackendKey struct {
	SvcID uint16
	Index uint16
	Gen   uint32
}

// Marshal encodes the key in the C struct's byte layout.
func (k BackendKey) Marshal() []byte {
	b := make([]byte, BackendKeySize)
	binary.LittleEndian.PutUint16(b[0:2], k.SvcID)
	binary.LittleEndian.PutUint16(b[2:4], k.Index)
	binary.LittleEndian.PutUint32(b[4:8], k.Gen)
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (k *BackendKey) Unmarshal(b []byte) error {
	if err := checkLen("backend_key", b, BackendKeySize); err != nil {
		return err
	}
	k.SvcID = binary.LittleEndian.Uint16(b[0:2])
	k.Index = binary.LittleEndian.Uint16(b[2:4])
	k.Gen = binary.LittleEndian.Uint32(b[4:8])
	return nil
}

// BackendVal is svc_backends' value: struct backend_val in kanea.c.
type BackendVal struct {
	IP   [4]byte // network order
	Port uint16  // host value here; encoded big-endian (__be16)
}

// Marshal encodes the value in the C struct's byte layout.
func (v BackendVal) Marshal() []byte {
	b := make([]byte, BackendValSize)
	copy(b[0:4], v.IP[:])
	binary.BigEndian.PutUint16(b[4:6], v.Port)
	// b[6:8] is explicit padding, always zero.
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *BackendVal) Unmarshal(b []byte) error {
	if err := checkLen("backend_val", b, BackendValSize); err != nil {
		return err
	}
	copy(v.IP[:], b[0:4])
	v.Port = binary.BigEndian.Uint16(b[4:6])
	return nil
}

// Identity is identity_v4's value: struct identity in kanea.c. The map's
// key is the pod IP itself, [4]byte network order (see IPKey). The numeric
// ids are Store-allocated and never reused (AGENTS.md, PRD v1.36).
type Identity struct {
	ProjectID uint32
	ServiceID uint32
	Flags     uint32 // bit 0: IdentityFlagHost
}

// Marshal encodes the value in the C struct's byte layout.
func (v Identity) Marshal() []byte {
	b := make([]byte, IdentitySize)
	binary.LittleEndian.PutUint32(b[0:4], v.ProjectID)
	binary.LittleEndian.PutUint32(b[4:8], v.ServiceID)
	binary.LittleEndian.PutUint32(b[8:12], v.Flags)
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *Identity) Unmarshal(b []byte) error {
	if err := checkLen("identity", b, IdentitySize); err != nil {
		return err
	}
	v.ProjectID = binary.LittleEndian.Uint32(b[0:4])
	v.ServiceID = binary.LittleEndian.Uint32(b[4:8])
	v.Flags = binary.LittleEndian.Uint32(b[8:12])
	return nil
}

// AllowKey is allow_v4's key: struct allow_key in kanea.c. The value is a
// single presence byte. Destination first: the lookup answers "may src
// connect to dst", from the receiving veth's point of view.
type AllowKey struct {
	DstServiceID uint32
	SrcServiceID uint32
}

// Marshal encodes the key in the C struct's byte layout.
func (k AllowKey) Marshal() []byte {
	b := make([]byte, AllowKeySize)
	binary.LittleEndian.PutUint32(b[0:4], k.DstServiceID)
	binary.LittleEndian.PutUint32(b[4:8], k.SrcServiceID)
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (k *AllowKey) Unmarshal(b []byte) error {
	if err := checkLen("allow_key", b, AllowKeySize); err != nil {
		return err
	}
	k.DstServiceID = binary.LittleEndian.Uint32(b[0:4])
	k.SrcServiceID = binary.LittleEndian.Uint32(b[4:8])
	return nil
}

// DropKey is stats_drops' key: struct drop_key in kanea.c.
type DropKey struct {
	DstIP  [4]byte // network order
	Reason uint8   // DropReason*
}

// Marshal encodes the key in the C struct's byte layout.
func (k DropKey) Marshal() []byte {
	b := make([]byte, DropKeySize)
	copy(b[0:4], k.DstIP[:])
	b[4] = k.Reason
	// b[5:8] is explicit padding, always zero.
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (k *DropKey) Unmarshal(b []byte) error {
	if err := checkLen("drop_key", b, DropKeySize); err != nil {
		return err
	}
	copy(k.DstIP[:], b[0:4])
	k.Reason = b[4]
	return nil
}

// EpStats is stats_ep's per-CPU value: struct ep_stats in kanea.c. The
// kernel hands userspace one of these per possible CPU; summing them is the
// reader's job.
type EpStats struct {
	RxBytes uint64
	RxPkts  uint64
	TxBytes uint64
	TxPkts  uint64
}

// Marshal encodes the value in the C struct's byte layout.
func (v EpStats) Marshal() []byte {
	b := make([]byte, EpStatsSize)
	binary.LittleEndian.PutUint64(b[0:8], v.RxBytes)
	binary.LittleEndian.PutUint64(b[8:16], v.RxPkts)
	binary.LittleEndian.PutUint64(b[16:24], v.TxBytes)
	binary.LittleEndian.PutUint64(b[24:32], v.TxPkts)
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *EpStats) Unmarshal(b []byte) error {
	if err := checkLen("ep_stats", b, EpStatsSize); err != nil {
		return err
	}
	v.RxBytes = binary.LittleEndian.Uint64(b[0:8])
	v.RxPkts = binary.LittleEndian.Uint64(b[8:16])
	v.TxBytes = binary.LittleEndian.Uint64(b[16:24])
	v.TxPkts = binary.LittleEndian.Uint64(b[24:32])
	return nil
}

// Config is config's single value: struct dp_config in kanea.c. Both
// fields are __be32 and travel in network order. A zero mask means "no
// service CIDR configured": the program guards on it, so the zero value
// an ARRAY map is born with drops nothing.
type Config struct {
	ServiceCIDRNet  [4]byte // network order
	ServiceCIDRMask [4]byte // network order
}

// Marshal encodes the value in the C struct's byte layout.
func (v Config) Marshal() []byte {
	b := make([]byte, ConfigSize)
	copy(b[0:4], v.ServiceCIDRNet[:])
	copy(b[4:8], v.ServiceCIDRMask[:])
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *Config) Unmarshal(b []byte) error {
	if err := checkLen("dp_config", b, ConfigSize); err != nil {
		return err
	}
	copy(v.ServiceCIDRNet[:], b[0:4])
	copy(v.ServiceCIDRMask[:], b[4:8])
	return nil
}

// CIDR is cluster_v4's single value: struct dp_cidr in kanea.c; one prefix
// as net+mask, both network order. A zero mask means "no cluster configured";
// the programs read that as the pre-v1.65 deny, so the value an ARRAY map is
// born with fails closed.
type CIDR struct {
	Net  [4]byte // network order
	Mask [4]byte // network order
}

// Marshal encodes the value in the C struct's byte layout.
func (v CIDR) Marshal() []byte {
	b := make([]byte, CIDRSize)
	copy(b[0:4], v.Net[:])
	copy(b[4:8], v.Mask[:])
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *CIDR) Unmarshal(b []byte) error {
	if err := checkLen("dp_cidr", b, CIDRSize); err != nil {
		return err
	}
	copy(v.Net[:], b[0:4])
	copy(v.Mask[:], b[4:8])
	return nil
}

// CIDR6 is cluster_v6's single value: struct dp_cidr6 in kanea.c.
type CIDR6 struct {
	Net  [16]byte // network order
	Mask [16]byte // network order
}

// Marshal encodes the value in the C struct's byte layout.
func (v CIDR6) Marshal() []byte {
	b := make([]byte, CIDR6Size)
	copy(b[0:16], v.Net[:])
	copy(b[16:32], v.Mask[:])
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *CIDR6) Unmarshal(b []byte) error {
	if err := checkLen("dp_cidr6", b, CIDR6Size); err != nil {
		return err
	}
	copy(v.Net[:], b[0:16])
	copy(v.Mask[:], b[16:32])
	return nil
}

// IPKey encodes a [4]byte address for the maps keyed by a bare __be32 pod
// IP (identity_v4, stats_ep): the wire bytes, unchanged.
func IPKey(ip [4]byte) []byte {
	b := make([]byte, StatsEpKeySize)
	copy(b, ip[:])
	return b
}

// SvcIDKey encodes a service id for stats_svc's bare __u16 key.
func SvcIDKey(id uint16) []byte {
	b := make([]byte, StatsSvcKeySize)
	binary.LittleEndian.PutUint16(b, id)
	return b
}

// SvcKey6 is svc_v6's key: struct svc_key6 in kanea.c (v1.41).
type SvcKey6 struct {
	VIP   [16]byte // network order, as on the wire
	Port  uint16   // host value here; encoded big-endian (__be16)
	Proto uint8    // IPPROTO_*; always TCP for v1 service ports
}

// Marshal encodes the key in the C struct's byte layout.
func (k SvcKey6) Marshal() []byte {
	b := make([]byte, SvcKey6Size)
	copy(b[0:16], k.VIP[:])
	binary.BigEndian.PutUint16(b[16:18], k.Port)
	b[18] = k.Proto
	// b[19] is explicit padding, always zero.
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (k *SvcKey6) Unmarshal(b []byte) error {
	if err := checkLen("svc_key6", b, SvcKey6Size); err != nil {
		return err
	}
	copy(k.VIP[:], b[0:16])
	k.Port = binary.BigEndian.Uint16(b[16:18])
	k.Proto = b[18]
	return nil
}

// BackendVal6 is svc_backends6's value: struct backend_val6 in kanea.c.
// The key is the shared BackendKey: the generation flip is one mechanism
// for both families.
type BackendVal6 struct {
	IP   [16]byte // network order
	Port uint16   // host value here; encoded big-endian (__be16)
}

// Marshal encodes the value in the C struct's byte layout.
func (v BackendVal6) Marshal() []byte {
	b := make([]byte, BackendVal6Size)
	copy(b[0:16], v.IP[:])
	binary.BigEndian.PutUint16(b[16:18], v.Port)
	// b[18:20] is explicit padding, always zero.
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *BackendVal6) Unmarshal(b []byte) error {
	if err := checkLen("backend_val6", b, BackendVal6Size); err != nil {
		return err
	}
	copy(v.IP[:], b[0:16])
	v.Port = binary.BigEndian.Uint16(b[16:18])
	return nil
}

// DropKey6 is stats_drops6's key: struct drop_key6 in kanea.c.
type DropKey6 struct {
	DstIP  [16]byte // network order
	Reason uint8    // DropReason*
}

// Marshal encodes the key in the C struct's byte layout.
func (k DropKey6) Marshal() []byte {
	b := make([]byte, DropKey6Size)
	copy(b[0:16], k.DstIP[:])
	b[16] = k.Reason
	// b[17:20] is explicit padding, always zero.
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (k *DropKey6) Unmarshal(b []byte) error {
	if err := checkLen("drop_key6", b, DropKey6Size); err != nil {
		return err
	}
	copy(k.DstIP[:], b[0:16])
	k.Reason = b[16]
	return nil
}

// Config6 is config6's single value: struct dp_config6 in kanea.c. An
// all-zero mask is the v6 enable switch read as "off": it is the value an
// ARRAY map is born with, so a node whose kanead never configured v6 fails
// closed (the tc programs drop ETH_P_IPV6 outright).
type Config6 struct {
	ServiceCIDRNet  [16]byte // network order
	ServiceCIDRMask [16]byte // network order
}

// Marshal encodes the value in the C struct's byte layout.
func (v Config6) Marshal() []byte {
	b := make([]byte, Config6Size)
	copy(b[0:16], v.ServiceCIDRNet[:])
	copy(b[16:32], v.ServiceCIDRMask[:])
	return b
}

// Unmarshal decodes the C struct's byte layout.
func (v *Config6) Unmarshal(b []byte) error {
	if err := checkLen("dp_config6", b, Config6Size); err != nil {
		return err
	}
	copy(v.ServiceCIDRNet[:], b[0:16])
	copy(v.ServiceCIDRMask[:], b[16:32])
	return nil
}

// IP6Key encodes a [16]byte address for the maps keyed by a bare
// struct in6_addr (identity_v6, stats_ep6): the wire bytes, unchanged.
func IP6Key(ip [16]byte) []byte {
	b := make([]byte, StatsEp6KeySize)
	copy(b, ip[:])
	return b
}
