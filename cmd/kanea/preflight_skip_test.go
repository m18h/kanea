package main

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// The third check outcome (PRD v1.86).
//
// `kanea doctor` run as an ordinary user reported FAIL for containerd ("exists
// but refuses connections") and for bpf, and closed with "this node has
// problems that will stop kanead working" - on a node where every one of those
// things was healthy and the only problem was that the checks needed root. The
// distinction being tested here is that "I could not look" is not "it is
// broken".

func TestAPermissionErrorIsNotAFinding(t *testing.T) {
	denied := []error{
		fs.ErrPermission,
		syscall.EACCES,
		syscall.EPERM,
		&os.PathError{Op: "stat", Path: "/sys/fs/bpf/kanea", Err: syscall.EACCES},
		&net.OpError{Op: "dial", Net: "unix", Err: syscall.EACCES},
	}
	for _, err := range denied {
		if !deniedByPermission(err) {
			t.Errorf("deniedByPermission(%v) = false, want true", err)
		}
	}

	// A real failure must keep failing: a socket that refuses connections is
	// the finding this outcome must not swallow.
	notDenied := []error{
		errors.New("connection refused"),
		syscall.ECONNREFUSED,
		&net.OpError{Op: "dial", Net: "unix", Err: syscall.ECONNREFUSED},
		&os.PathError{Op: "stat", Path: "/x", Err: syscall.ENOENT},
	}
	for _, err := range notDenied {
		if deniedByPermission(err) {
			t.Errorf("deniedByPermission(%v) = true, want false", err)
		}
	}
}

// A skipped check leaves the node's verdict alone. Counting one as a failure is
// what produced the "this node has problems" line on a healthy node.
func TestASkippedCheckIsNotAFailure(t *testing.T) {
	s := skip("containerd", "not checked: needs root")
	if !s.OK || !s.Skipped {
		t.Fatalf("skip() = %+v, want OK and Skipped", s)
	}

	var buf strings.Builder
	o := &out{w: &buf}
	ok, skipped := renderCheckResults(o, []checkResult{
		pass("platform", "linux/amd64"),
		s,
		warn("buildkit", "socket is absent", "start it"),
	})
	if !ok {
		t.Fatal("a run with a skip and a warn reported the node broken")
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
	rendered := buf.String()
	if !strings.Contains(rendered, "SKIP  containerd") {
		t.Fatalf("the skip is not rendered as one:\n%s", rendered)
	}
	if strings.Contains(rendered, "FAIL") {
		t.Fatalf("a skip rendered as a failure:\n%s", rendered)
	}
	// The fix line matters: a SKIP with no instruction reads as a check that
	// is simply broken.
	if !strings.Contains(rendered, "re-run as root") {
		t.Fatalf("the skip does not say how to resolve it:\n%s", rendered)
	}
}

// A genuine failure still clears the verdict, which is the property the skip
// outcome must not have loosened.
func TestARealFailureStillFails(t *testing.T) {
	var buf strings.Builder
	o := &out{w: &buf}
	ok, skipped := renderCheckResults(o, []checkResult{
		skip("bpf", "not checked: needs root"),
		fail("cgroups v2", "not the unified hierarchy", "boot with cgroup2"),
	})
	if ok {
		t.Fatal("a failing check did not clear the verdict")
	}
	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1", skipped)
	}
}
