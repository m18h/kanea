//go:build linux

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/google/nftables"
)

const (
	cgroupRoot = "/sys/fs/cgroup"

	podCIDRStr = "10.244.0.0/16"
	gwIPStr    = "10.244.0.1"
	svcCIDRStr = "10.201.0.0/16"

	dummyName = "kanea0-spike"
	nsPrefix  = "ksp-"  // netns names: ksp-<pod id>
	vePrefix  = "kspv-" // host-side veth names: kspv-<pod id>
	pePrefix  = "kspp-" // temporary peer names before the rename to eth0

	projA uint32 = 1
	projB uint32 = 2

	svcClientA uint32 = 11 // p1
	svcServerA uint32 = 12 // p2, p3
	svcOtherB  uint32 = 21 // p4
	svcTempB   uint32 = 22 // p5, check 3 only

	vip1 = "10.201.0.1" // LB across p2:8080 and p3:8080
	vip2 = "10.201.0.2" // zero backends
	vip3 = "10.201.0.3" // hairpin -> p1:8080
	vip4 = "10.201.0.4" // generation-flip target (check 9)

	vipSvc1 uint16 = 1
	vipSvc2 uint16 = 2
	vipSvc3 uint16 = 3
	vipSvc4 uint16 = 4

	vipPort     = 80
	backendPort = 8080
)

// flipPorts: check 9 tells backend generations apart by listen port.
var (
	gen1Ports = []int{9101, 9102}
	gen2Ports = []int{9201, 9202}
)

type pod struct {
	id      string
	ns      string // netns name
	ip      net.IP
	veth    string // host-side veth name
	project uint32
	service uint32
}

type env struct {
	objPath string

	spec        *ebpf.CollectionSpec
	coll        *ebpf.Collection
	svcMap      *ebpf.Map
	backendMap  *ebpf.Map
	identityMap *ebpf.Map
	allowMap    *ebpf.Map
	statsSvc    *ebpf.Map
	statsDrops  *ebpf.Map
	statsEp     *ebpf.Map

	connect4      *ebpf.Program
	toContainer   *ebpf.Program
	fromContainer *ebpf.Program

	cgLink   link.Link
	loadTime time.Duration

	uplinkName string
	uplinkIP   net.IP

	pods      map[string]*pod
	podAttach map[string]time.Duration // full veth+tc+maps sequence per pod

	nft *nftables.Conn

	// snapshot of every cgroup attach point BEFORE our own attach (check 1c)
	preAttach map[ebpf.AttachType][]ebpf.ProgramID

	sysctls map[string]string // saved values to restore
	servers []*exec.Cmd
}

var allChecks = []struct {
	num   int
	title string
	fn    func(*env) error
}{
	{1, "connect4 at the root cgroup (host + netns/systemd cgroup, ALLOW_MULTI)", check1},
	{2, "pinned cgroup link survives loader exit; Link.Update under load", check2},
	{3, "tc filters: loader exit, atomic replace, veth deletion", check3},
	{4, "end-to-end: pod->VIP->pod, host->VIP, hairpin, EPERM, masquerade", check4},
	{5, "SYN-gated policy: same project, cross project, allow edge, ICMP", check5},
	{6, "netfilter interplay: FORWARD policy drop (docker/ufw simulation)", check6},
	{7, "strict rp_filter and PERMANENT neighbors", check7},
	{8, "measurements: connect latency, attach latency, memory, verify time", check8},
	{9, "batch map ops and the generation-flip update pattern", check9},
	{10, "getpeername after connect-time DNAT", check10},
	{11, "BPF_PROG_TEST_RUN for SCHED_CLS; bpf_sock_addr.protocol probe", check11},
	{12, "dual-stack (v1.41): shipping object, connect6, tc v6 policy, disabled-mode drop", check12},
}

func main() {
	// Hidden child modes (__serve, __connect, ...) re-exec this binary.
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "__") {
		childMain()
		return
	}

	only := flag.String("only", "", "comma-separated check numbers to run, e.g. 1,4,5")
	cleanup := flag.Bool("cleanup", false, "purge leftover spike state from a crashed run and exit")
	obj := flag.String("bpf", "bpf/spike.o", "compiled BPF object (produced by build.sh)")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "this spike needs root (cgroup bpf, netns, tc, nftables)")
		os.Exit(2)
	}
	if *cleanup {
		purge()
		return
	}
	sel, err := parseOnly(*only)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad -only: %v\n", err)
		os.Exit(2)
	}
	os.Exit(run(*obj, sel))
}

func run(objPath string, sel map[int]bool) int {
	e, err := setup(objPath)
	if e != nil {
		defer teardown(e)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		return 1
	}

	for _, c := range allChecks {
		if sel != nil && !sel[c.num] {
			continue
		}
		fmt.Printf("\n── %d. %s ──\n", c.num, c.title)
		if err := c.fn(e); err != nil {
			check(fmt.Sprintf("check %d aborted", c.num), false, err.Error())
		}
	}
	if err := summary(); err != nil {
		fmt.Fprintf(os.Stderr, "\nOVERALL: FAIL (%v)\n", err)
		return 1
	}
	fmt.Println("\nOVERALL: PASS")
	return 0
}

func parseOnly(s string) (map[int]bool, error) {
	if s == "" {
		return nil, nil
	}
	sel := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > len(allChecks) {
			return nil, fmt.Errorf("%q is not a check number (1-%d)", part, len(allChecks))
		}
		sel[n] = true
	}
	return sel, nil
}

// ---- setup / teardown ----

func setup(objPath string) (*env, error) {
	e := &env{
		objPath:   objPath,
		pods:      map[string]*pod{},
		podAttach: map[string]time.Duration{},
		sysctls:   map[string]string{},
	}
	if err := checkBpffs(); err != nil {
		return e, err
	}
	if err := saveAndSetSysctl(e, "net/ipv4/ip_forward", "1"); err != nil {
		return e, err
	}

	// The pre-attach snapshot (check 1c) has to happen before our attach.
	e.preAttach = queryCgroupPrograms()

	if err := loadAndPin(e); err != nil {
		return e, err
	}
	l, err := attachConnect4(e.connect4)
	if err != nil {
		return e, fmt.Errorf("attach connect4 at %s: %w", cgroupRoot, err)
	}
	e.cgLink = l

	if err := findUplink(e); err != nil {
		return e, err
	}
	if err := hostAnchor(e); err != nil {
		return e, err
	}
	if err := nftSetup(e); err != nil {
		return e, err
	}

	// Host identities: anything the host originates from is HOST-flagged.
	if err := setIdentity(e, net.ParseIP(gwIPStr), 0, 0, flagHost); err != nil {
		return e, err
	}
	if err := setIdentity(e, e.uplinkIP, 0, 0, flagHost); err != nil {
		return e, err
	}

	for _, p := range []struct {
		id               string
		ip               string
		project, service uint32
	}{
		{"p1", "10.244.0.11", projA, svcClientA},
		{"p2", "10.244.0.12", projA, svcServerA},
		{"p3", "10.244.0.13", projA, svcServerA},
		{"p4", "10.244.0.14", projB, svcOtherB},
	} {
		if _, err := createPod(e, p.id, net.ParseIP(p.ip), p.project, p.service); err != nil {
			return e, fmt.Errorf("create pod %s: %w", p.id, err)
		}
	}

	// VIPs. vip4 is programmed by check 9 itself.
	if err := setService(e, vip1, vipPort, vipSvc1, 2, 1); err != nil {
		return e, err
	}
	if err := putBackend(e, vipSvc1, 0, 1, e.pods["p2"].ip, backendPort); err != nil {
		return e, err
	}
	if err := putBackend(e, vipSvc1, 1, 1, e.pods["p3"].ip, backendPort); err != nil {
		return e, err
	}
	if err := setService(e, vip2, vipPort, vipSvc2, 0, 1); err != nil {
		return e, err
	}
	if err := setService(e, vip3, vipPort, vipSvc3, 1, 1); err != nil {
		return e, err
	}
	if err := putBackend(e, vipSvc3, 0, 1, e.pods["p1"].ip, backendPort); err != nil {
		return e, err
	}

	// Servers: p1 is also the hairpin backend; p2 additionally carries the
	// generation-flip ports for check 9.
	if err := startServer(e, "p1", backendPort); err != nil {
		return e, err
	}
	if err := startServer(e, "p2", append([]int{backendPort}, append(gen1Ports, gen2Ports...)...)...); err != nil {
		return e, err
	}
	if err := startServer(e, "p3", backendPort); err != nil {
		return e, err
	}
	return e, nil
}

func teardown(e *env) {
	fmt.Println("\n── teardown ──")
	for _, cmd := range e.servers {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	for id := range e.pods {
		deletePod(e, id)
	}
	nftTeardown(e)
	removeHostAnchor()
	if e.cgLink != nil {
		_ = e.cgLink.Unpin()
		_ = e.cgLink.Close()
	}
	if e.coll != nil {
		e.coll.Close()
	}
	_ = os.RemoveAll(pinRoot)
	restoreSysctls(e)
}

// ---- PASS/FAIL bookkeeping (feeds REPORT.md verbatim) ----

type checkResult struct {
	name   string
	ok     bool
	detail string
}

var results []checkResult

func check(name string, ok bool, detail string) {
	results = append(results, checkResult{name, ok, detail})
	mark := "PASS"
	if !ok {
		mark = "FAIL"
	}
	if detail != "" {
		fmt.Printf("%s  %-58s %s\n", mark, name, detail)
	} else {
		fmt.Printf("%s  %s\n", mark, name)
	}
}

// info records an observation that is not a go/no-go criterion.
func info(name, detail string) {
	fmt.Printf("INFO  %-58s %s\n", name, detail)
}

func summary() error {
	bad := 0
	for _, r := range results {
		if !r.ok {
			bad++
		}
	}
	fmt.Printf("\n== %d/%d checks passed ==\n", len(results)-bad, len(results))
	if bad > 0 {
		return fmt.Errorf("%d checks failed", bad)
	}
	return nil
}
