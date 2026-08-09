//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

func self() string {
	p, err := os.Executable()
	if err != nil {
		panic(err)
	}
	return p
}

// childMain dispatches the hidden re-exec modes. They exist because a
// connect(2) "from inside a pod" has to happen in that pod's netns, and
// `ip netns exec <ns> <this binary> __mode ...` is the cheapest honest way
// to get there. __childload and __childtc exist to prove that pinned
// state outlives the process that created it (checks 2 and 3).
func childMain() {
	var err error
	switch os.Args[1] {
	case "__serve":
		err = childServe(os.Args[2:])
	case "__connect":
		err = childConnect(os.Args[2:])
	case "__hammer":
		err = childHammer(os.Args[2:])
	case "__childload":
		err = childLoad()
	case "__childtc":
		err = childTC(os.Args[2:])
	default:
		err = fmt.Errorf("unknown child mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

// __serve <port>... — listen on every port; each accepted connection gets a
// one-line banner naming the address that served it, which is how a client
// learns which backend a VIP connect actually landed on.
func childServe(ports []string) error {
	if len(ports) == 0 {
		return errors.New("usage: __serve <port>...")
	}
	for _, port := range ports {
		ln, err := net.Listen("tcp", ":"+port)
		if err != nil {
			return err
		}
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					fmt.Fprintf(c, "KANEA %s\n", c.LocalAddr())
				}(conn)
			}
		}(ln)
	}
	fmt.Println("READY")
	select {}
}

// __connect <addr> <timeoutMS> — one dial; prints a parseable result line.
func childConnect(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: __connect <addr> <timeoutMS>")
	}
	ms, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	t0 := time.Now()
	banner, peer, err := dialAndRead(args[0], time.Duration(ms)*time.Millisecond)
	elapsed := time.Since(t0)
	if err != nil {
		fmt.Printf("ERR elapsed_ms=%d err=%q\n", elapsed.Milliseconds(), err.Error())
		return nil // the caller parses stdout; a refused connect is data, not failure
	}
	fmt.Printf("OK banner=%q peer=%s elapsed_ms=%d\n", banner, peer, elapsed.Milliseconds())
	return nil
}

// __hammer <addr> <durMS> <concurrency> — dial in a loop, tally per-backend
// counts and errors. Its output is what the atomicity checks assert on.
func childHammer(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: __hammer <addr> <durMS> <concurrency>")
	}
	durMS, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	conc, err := strconv.Atoi(args[2])
	if err != nil {
		return err
	}
	var (
		mu       sync.Mutex
		counts   = map[string]int{}
		errCount int
		firstErr string
	)
	deadline := time.Now().Add(time.Duration(durMS) * time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				banner, _, err := dialAndRead(args[0], 2*time.Second)
				mu.Lock()
				if err != nil {
					errCount++
					if firstErr == "" {
						firstErr = err.Error()
					}
				} else {
					counts[bannerAddr(banner)]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("count %s %d\n", k, counts[k])
	}
	fmt.Printf("errors %d first=%q\n", errCount, firstErr)
	return nil
}

// __childload — re-attach the pinned connect4 program at the root cgroup
// and pin the new link, then exit. The parent verifies the rewrite still
// happens once this process is gone.
func childLoad() error {
	prog, err := ebpf.LoadPinnedProgram(pinProgs+"/"+progConnect4, nil)
	if err != nil {
		return err
	}
	defer prog.Close()
	l, err := attachConnect4(prog)
	if err != nil {
		return err
	}
	// Deliberately no Close: exiting IS the point. The pin keeps it alive.
	_ = l
	fmt.Println("ATTACHED")
	return nil
}

// __childtc <ifname> — attach the pinned tc programs to an interface the
// parent created, then exit.
func childTC(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: __childtc <ifname>")
	}
	toC, err := ebpf.LoadPinnedProgram(pinProgs+"/"+progToContainer, nil)
	if err != nil {
		return err
	}
	defer toC.Close()
	fromC, err := ebpf.LoadPinnedProgram(pinProgs+"/"+progFromContainer, nil)
	if err != nil {
		return err
	}
	defer fromC.Close()
	lnk, err := netlink.LinkByName(args[0])
	if err != nil {
		return err
	}
	if err := attachTC(lnk.Attrs().Index, toC, fromC); err != nil {
		return err
	}
	fmt.Println("ATTACHED")
	return nil
}

// ---- parent-side helpers ----

func dialAndRead(addr string, timeout time.Duration) (banner, peer string, err error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	peer = getpeername(conn)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", peer, fmt.Errorf("read banner: %w", err)
	}
	return strings.TrimSpace(line), peer, nil
}

// getpeername reads the peer address with the raw syscall, not from Go's
// bookkeeping — check 10 is about what the kernel says after the DNAT.
func getpeername(conn net.Conn) string {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return conn.RemoteAddr().String()
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return conn.RemoteAddr().String()
	}
	var out string
	_ = raw.Control(func(fd uintptr) {
		sa, err := syscall.Getpeername(int(fd))
		if err != nil {
			out = fmt.Sprintf("getpeername:%v", err)
			return
		}
		if sa4, ok := sa.(*syscall.SockaddrInet4); ok {
			out = fmt.Sprintf("%s:%d", net.IP(sa4.Addr[:]), sa4.Port)
		}
	})
	if out == "" {
		return conn.RemoteAddr().String()
	}
	return out
}

func bannerAddr(banner string) string {
	if rest, ok := strings.CutPrefix(banner, "KANEA "); ok {
		return rest
	}
	return banner
}

// startServer launches __serve inside a pod's netns and waits until every
// port accepts (host->pod passes P2's HOST gate, so the poll is also a
// smoke test of the plumbing).
func startServer(e *env, podID string, ports ...int) error {
	p := e.pods[podID]
	args := []string{"netns", "exec", p.ns, self(), "__serve"}
	for _, port := range ports {
		args = append(args, strconv.Itoa(port))
	}
	cmd := exec.Command("ip", args...)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	e.servers = append(e.servers, cmd)
	for _, port := range ports {
		addr := fmt.Sprintf("%s:%d", p.ip, port)
		var lastErr error
		for i := 0; i < 30; i++ {
			_, _, lastErr = dialAndRead(addr, 500*time.Millisecond)
			if lastErr == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if lastErr != nil {
			return fmt.Errorf("server %s did not come up on %s: %w", podID, addr, lastErr)
		}
	}
	return nil
}

// podConnect runs one __connect inside a pod's netns, optionally wrapped in
// a transient systemd scope (check 1b).
func podConnect(e *env, podID, addr string, timeout time.Duration, viaSystemdScope bool) (ok bool, banner string, elapsed time.Duration, errText string, err error) {
	p := e.pods[podID]
	args := []string{"ip", "netns", "exec", p.ns, self(), "__connect", addr,
		strconv.Itoa(int(timeout.Milliseconds()))}
	if viaSystemdScope {
		args = append([]string{"systemd-run", "--scope", "--quiet", "--"}, args...)
	}
	out, runErr := exec.Command(args[0], args[1:]...).Output()
	if runErr != nil {
		return false, "", 0, "", fmt.Errorf("%v: %s", runErr, out)
	}
	return parseConnectLine(string(out))
}

func parseConnectLine(out string) (ok bool, banner string, elapsed time.Duration, errText string, err error) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		kv := map[string]string{}
		for _, f := range fields[1:] {
			if k, v, found := strings.Cut(f, "="); found {
				kv[k] = v
			}
		}
		ms, _ := strconv.Atoi(kv["elapsed_ms"])
		elapsed = time.Duration(ms) * time.Millisecond
		switch fields[0] {
		case "OK":
			b, _ := strconv.Unquote(kv["banner"])
			return true, b, elapsed, "", nil
		case "ERR":
			t, _ := strconv.Unquote(kv["err"])
			return false, "", elapsed, t, nil
		}
	}
	return false, "", 0, "", fmt.Errorf("no result line in %q", out)
}

// podHammer runs __hammer inside a pod's netns and parses its tallies.
func podHammer(e *env, podID, addr string, dur time.Duration, conc int) (counts map[string]int, errCount int, firstErr string, err error) {
	p := e.pods[podID]
	out, runErr := exec.Command("ip", "netns", "exec", p.ns, self(), "__hammer",
		addr, strconv.Itoa(int(dur.Milliseconds())), strconv.Itoa(conc)).Output()
	if runErr != nil {
		return nil, 0, "", fmt.Errorf("%v: %s", runErr, out)
	}
	counts = map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 3 && fields[0] == "count":
			n, _ := strconv.Atoi(fields[2])
			counts[fields[1]] = n
		case len(fields) >= 2 && fields[0] == "errors":
			errCount, _ = strconv.Atoi(fields[1])
			if len(fields) >= 3 {
				firstErr = strings.TrimPrefix(fields[2], "first=")
			}
		}
	}
	return counts, errCount, firstErr, nil
}

// podPing runs one ICMP echo from inside a pod; the result is recorded, not
// asserted blindly (check 5's ICMP question is "what happens?").
func podPing(e *env, podID, target string) (ok bool, out string) {
	p := e.pods[podID]
	b, err := exec.Command("ip", "netns", "exec", p.ns, "ping", "-c", "1", "-W", "1", target).CombinedOutput()
	return err == nil, strings.TrimSpace(string(b))
}

func isEPERM(errText string) bool {
	return strings.Contains(errText, "operation not permitted") || strings.Contains(errText, "EPERM")
}

// hostDial dials from the harness process itself (the "plain host process"
// of check 1a and the kanea-edge stand-in everywhere else).
func hostDial(addr string, timeout time.Duration) (banner, peer string, elapsed time.Duration, err error) {
	t0 := time.Now()
	banner, peer, err = dialAndRead(addr, timeout)
	return banner, peer, time.Since(t0), err
}
