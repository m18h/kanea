//go:build linux

package main

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// Pin layout — a spike-specific root so nothing here can ever collide with
// another user of bpffs.
const (
	pinRoot         = "/sys/fs/bpf/kanea-spike"
	pinMaps         = pinRoot + "/maps"
	pinProgs        = pinRoot + "/progs"
	pinLinks        = pinRoot + "/links"
	pinConnect4Link = pinLinks + "/connect4"

	progConnect4      = "kanea_connect4"
	progConnect4Proto = "kanea_connect4_proto"
	progToContainer   = "kanea_to_container"
	progFromContainer = "kanea_from_container"

	flagHost uint32 = 0x1
)

// stats_drops indices — mirror bpf/spike.c.
const (
	dropIDMiss uint32 = iota
	dropPolicy
	dropLinkLocal
	dropSvcCIDR
)

// The layouts below mirror bpf/spike.c byte for byte. Network-order fields
// are byte arrays so no marshalling step can quietly re-order them.

type svcKey struct {
	IP    [4]byte
	Port  [2]byte // network byte order, like bpf_sock_addr.user_port
	Proto uint8
	Pad   uint8
}

type svcVal struct {
	SvcID uint16
	Count uint16
	Gen   uint32
}

type backendKey struct {
	SvcID uint16
	Index uint16
	Gen   uint32
}

type backendVal struct {
	IP   [4]byte
	Port [2]byte
	Pad  uint16
}

type identityVal struct {
	ProjectID uint32
	ServiceID uint32
	Flags     uint32
}

type allowKey struct {
	DstServiceID uint32
	SrcServiceID uint32
}

type epStats struct {
	Pkts  uint64
	Bytes uint64
}

const protoTCP = 6

func be2(port uint16) [2]byte { return [2]byte{byte(port >> 8), byte(port)} }

func be4(ip net.IP) [4]byte {
	var b [4]byte
	copy(b[:], ip.To4())
	return b
}

func newSvcKey(vip string, port uint16) svcKey {
	return svcKey{IP: be4(net.ParseIP(vip)), Port: be2(port), Proto: protoTCP}
}

func setService(e *env, vip string, port uint16, svcID, count uint16, gen uint32) error {
	k := newSvcKey(vip, port)
	v := svcVal{SvcID: svcID, Count: count, Gen: gen}
	if err := e.svcMap.Put(k, v); err != nil {
		return fmt.Errorf("svc_v4 put %s:%d: %w", vip, port, err)
	}
	return nil
}

func putBackend(e *env, svcID, index uint16, gen uint32, ip net.IP, port uint16) error {
	k := backendKey{SvcID: svcID, Index: index, Gen: gen}
	v := backendVal{IP: be4(ip), Port: be2(port)}
	if err := e.backendMap.Put(k, v); err != nil {
		return fmt.Errorf("svc_backends put %d/%d/g%d: %w", svcID, index, gen, err)
	}
	return nil
}

func delBackend(e *env, svcID, index uint16, gen uint32) error {
	return e.backendMap.Delete(backendKey{SvcID: svcID, Index: index, Gen: gen})
}

func setIdentity(e *env, ip net.IP, project, service, flags uint32) error {
	v := identityVal{ProjectID: project, ServiceID: service, Flags: flags}
	if err := e.identityMap.Put(be4(ip), v); err != nil {
		return fmt.Errorf("identity_v4 put %s: %w", ip, err)
	}
	return nil
}

func allowEdge(e *env, dstService, srcService uint32) error {
	return e.allowMap.Put(allowKey{DstServiceID: dstService, SrcServiceID: srcService}, uint8(1))
}

func denyEdge(e *env, dstService, srcService uint32) error {
	return e.allowMap.Delete(allowKey{DstServiceID: dstService, SrcServiceID: srcService})
}

// readDrops sums the per-cpu drop counter for one reason.
func readDrops(e *env, reason uint32) (uint64, error) {
	var per []uint64
	if err := e.statsDrops.Lookup(reason, &per); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range per {
		sum += v
	}
	return sum, nil
}

// readSvcConnects sums the per-cpu connect counter for one service.
func readSvcConnects(e *env, svcID uint16) (uint64, error) {
	var per []uint64
	if err := e.statsSvc.Lookup(uint32(svcID), &per); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range per {
		sum += v
	}
	return sum, nil
}

// readEpStats sums the per-cpu tx accounting for one endpoint IP.
func readEpStats(e *env, ip net.IP) (epStats, error) {
	var per []epStats
	if err := e.statsEp.Lookup(be4(ip), &per); err != nil {
		if err == ebpf.ErrKeyNotExist {
			return epStats{}, nil
		}
		return epStats{}, err
	}
	var sum epStats
	for _, v := range per {
		sum.Pkts += v.Pkts
		sum.Bytes += v.Bytes
	}
	return sum, nil
}
