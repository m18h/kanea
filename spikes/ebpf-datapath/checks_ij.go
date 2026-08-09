//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
)

// check9 — batch map ops and the generation-flip update pattern.
func check9(e *env) error {
	// 9a: do BatchUpdate/BatchLookup/BatchDelete work on this kernel? They do
	// not on the 5.10 floor for HASH maps in older point releases — record
	// the errno rather than treating absence as failure.
	batchOK, batchDetail := probeBatch()
	info("9a batch map ops", batchDetail)
	// Not a go/no-go by itself; the generation-flip pattern below is the one
	// that must work, and it is written to NOT require batch ops.
	check("9a batch map ops probed (result recorded)", true, "supported="+boolText(batchOK))

	// 9b: the generation-flip update pattern under concurrent connect load.
	// gen 1 backends: p2 on gen1Ports. gen 2: p2 on gen2Ports. A connect that
	// ever lands on a mixed/torn set is distinguishable by port.
	if err := putBackend(e, vipSvc4, 0, 1, e.pods["p2"].ip, uint16(gen1Ports[0])); err != nil {
		check("9b generation-flip: no torn connect", false, err.Error())
		return nil
	}
	if err := putBackend(e, vipSvc4, 1, 1, e.pods["p2"].ip, uint16(gen1Ports[1])); err != nil {
		check("9b generation-flip: no torn connect", false, err.Error())
		return nil
	}
	if err := setService(e, vip4, vipPort, vipSvc4, 2, 1); err != nil {
		check("9b generation-flip: no torn connect", false, err.Error())
		return nil
	}

	done := make(chan hammerResult, 1)
	go func() {
		counts, errCount, firstErr, herr := podHammer(e, "p1", fmt.Sprintf("%s:%d", vip4, vipPort), 1500*time.Millisecond, 8)
		done <- hammerResult{counts, errCount, firstErr, herr}
	}()

	// Flip generations a few times while the hammer runs. Each flip: write the
	// NEW gen backends, single svc_v4 update to the new gen, delete OLD gen.
	time.Sleep(200 * time.Millisecond)
	curGen := uint32(1)
	for i := 0; i < 4; i++ {
		newGen := curGen + 1
		newPorts := gen2Ports
		if newGen%2 == 1 {
			newPorts = gen1Ports
		}
		_ = putBackend(e, vipSvc4, 0, newGen, e.pods["p2"].ip, uint16(newPorts[0]))
		_ = putBackend(e, vipSvc4, 1, newGen, e.pods["p2"].ip, uint16(newPorts[1]))
		_ = setService(e, vip4, vipPort, vipSvc4, 2, newGen) // single atomic swap of the pointer
		_ = delBackend(e, vipSvc4, 0, curGen)
		_ = delBackend(e, vipSvc4, 1, curGen)
		curGen = newGen
		time.Sleep(150 * time.Millisecond)
	}
	res := <-done
	if res.err != nil {
		check("9b generation-flip: no torn connect", false, res.err.Error())
		return nil
	}
	// Every served backend must be a valid gen1 OR gen2 port; none other, and
	// zero errors (a torn read would EPERM and show as an error).
	valid := map[string]bool{}
	for _, p := range append(append([]int{}, gen1Ports...), gen2Ports...) {
		valid[fmt.Sprintf("%s:%d", e.pods["p2"].ip, p)] = true
	}
	bad := ""
	total := 0
	for addr, n := range res.counts {
		total += n
		if !valid[addr] {
			bad = addr
		}
	}
	ok := res.errCount == 0 && bad == "" && total > 0
	check("9b generation-flip: no torn connect (mixed-gen distinguishable by port)", ok,
		fmt.Sprintf("%d connects, backends=%v, errors=%d, unexpected=%q", total, res.counts, res.errCount, bad))
	return nil
}

func probeBatch() (bool, string) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 16,
	})
	if err != nil {
		return false, "probe map: " + err.Error()
	}
	defer m.Close()

	keys := []uint32{1, 2, 3}
	vals := []uint64{10, 20, 30}
	n, err := m.BatchUpdate(keys, vals, nil)
	if err != nil {
		return false, "BatchUpdate: " + errnoText(err)
	}
	outK := make([]uint32, 3)
	outV := make([]uint64, 3)
	var cursor ebpf.MapBatchCursor
	if _, err := m.BatchLookup(&cursor, outK, outV, nil); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Sprintf("BatchUpdate ok (%d) but BatchLookup: %s", n, errnoText(err))
	}
	if _, err := m.BatchDelete(keys, nil); err != nil {
		return false, fmt.Sprintf("BatchUpdate/Lookup ok but BatchDelete: %s", errnoText(err))
	}
	return true, fmt.Sprintf("BatchUpdate/Lookup/Delete all work (updated %d)", n)
}

func errnoText(err error) string {
	return err.Error()
}

// check10 — getpeername after connect-time DNAT: does it return the backend
// address (no fixup program needed) or the VIP (fixup needed)?
func check10(e *env) error {
	vipAddr := fmt.Sprintf("%s:%d", vip3, vipPort) // hairpin: single backend p1
	_, peer, _, err := hostDial(vipAddr, 3*time.Second)
	if err != nil {
		check("10 getpeername after DNAT recorded", false, err.Error())
		return nil
	}
	backend := fmt.Sprintf("%s:%d", e.pods["p1"].ip, backendPort)
	isBackend := peer == backend
	isVIP := peer == vipAddr
	info("10 getpeername returned", peer)
	// Recorded finding: if it returns the backend, no getpeername fixup
	// program is needed; if the VIP, one is.
	detail := fmt.Sprintf("peer=%s backend=%s vip=%s -> %s", peer, backend, vipAddr,
		fixupVerdict(isBackend, isVIP))
	check("10 getpeername after DNAT recorded", isBackend || isVIP, detail)
	return nil
}

func fixupVerdict(isBackend, isVIP bool) string {
	switch {
	case isBackend:
		return "backend addr: NO fixup program needed"
	case isVIP:
		return "VIP addr: a getpeername fixup program IS needed"
	default:
		return "neither (unexpected)"
	}
}

// check11 — BPF_PROG_TEST_RUN for the SCHED_CLS programs, and the
// bpf_sock_addr.protocol compile/verify probe.
func check11(e *env) error {
	// 11a: run P2 (to_container) against a crafted cross-project SYN — expect
	// TC_ACT_SHOT (2) — and a crafted non-SYN — expect TC_ACT_OK (0).
	src := e.pods["p1"].ip // projA
	dst := e.pods["p4"].ip // projB
	syn := buildTCPPacket(src, dst, tcpSYN)
	ack := buildTCPPacket(src, dst, tcpACK)

	synRet, synErr := runSchedCLS(e.toContainer, syn)
	if synErr != nil {
		check("11a PROG_TEST_RUN on SCHED_CLS usable at this kernel", false, errnoText(synErr))
		// If test_run is unsupported, the protocol probe still runs below.
	} else {
		ackRet, ackErr := runSchedCLS(e.toContainer, ack)
		if ackErr != nil {
			check("11a PROG_TEST_RUN on SCHED_CLS usable at this kernel", false, errnoText(ackErr))
		} else {
			ok := synRet == tcActShot && ackRet == tcActOK
			check("11a PROG_TEST_RUN: cross-proj SYN=SHOT, non-SYN=OK", ok,
				fmt.Sprintf("syn_verdict=%d (want %d), ack_verdict=%d (want %d)", synRet, tcActShot, ackRet, tcActOK))
		}
	}

	// 11b: does bpf_sock_addr have a usable `protocol` field at this kernel?
	// Load the kanea_connect4_proto variant that reads ctx->protocol.
	protoErr := loadProtoProbe(e)
	if protoErr == nil {
		check("11b bpf_sock_addr.protocol usable (variant verifies)", true, "ctx->protocol verified and loaded")
	} else {
		// A verify failure here is the finding, not a harness bug — record it.
		info("11b protocol-field load error", protoErr.Error())
		check("11b bpf_sock_addr.protocol usable (variant verifies)", false,
			"variant did NOT verify — gate on ctx->type only at the floor")
	}
	return nil
}

const (
	tcActOK   = 0
	tcActShot = 2

	tcpSYN = 0x02
	tcpACK = 0x10
)

// runSchedCLS invokes BPF_PROG_TEST_RUN with an L2 frame and returns the
// program's return code (the tc verdict).
func runSchedCLS(prog *ebpf.Program, frame []byte) (uint32, error) {
	out := make([]byte, len(frame)+64)
	ret, err := prog.Run(&ebpf.RunOptions{Data: frame, DataOut: out})
	return ret, err
}

// buildTCPPacket assembles eth + IPv4 + TCP with the given flags, matching
// the raw-byte header layout the BPF programs parse.
func buildTCPPacket(src, dst net.IP, flags byte) []byte {
	eth := make([]byte, 14)
	// dst/src MAC left zero; ethertype IPv4.
	binary.BigEndian.PutUint16(eth[12:], 0x0800)

	ip := make([]byte, 20)
	ip[0] = 0x45 // version 4, ihl 5
	binary.BigEndian.PutUint16(ip[2:], 40)
	ip[8] = 64 // ttl
	ip[9] = protoTCP
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 40000) // src port
	binary.BigEndian.PutUint16(tcp[2:], backendPort)
	tcp[12] = 0x50 // data offset 5
	tcp[13] = flags

	frame := append(eth, ip...)
	frame = append(frame, tcp...)
	return frame
}
