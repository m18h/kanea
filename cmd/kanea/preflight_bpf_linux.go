//go:build linux

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/m18h/kanea/internal/datapath/dpmap"
)

// Filesystem magic numbers, from the kernel's own statfs(2) documentation:
// BPF_FS_MAGIC and CGROUP2_SUPER_MAGIC.
const (
	bpffsMagic   = 0xcafe4a11
	cgroup2Magic = 0x63677270
)

// checkBPF verifies what the eBPF datapath needs before the first program
// load: a bpffs to pin under, the unified cgroup hierarchy to attach the
// connect-time LB link to, and a pin directory kanead can create.
//
// Checked here rather than left to kanead's own startup because an Init
// failure is a hard startup error in ebpf mode (there is no external agent to
// wait for) and `doctor` should name the cause before systemd shows the
// symptom as a restart loop.
func checkBPF() checkResult {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/bpf", &stat); err != nil {
		return fail("bpf", "/sys/fs/bpf: "+err.Error(),
			"mount -t bpf bpf /sys/fs/bpf; the datapath pins its maps, programs "+
				"and links there, and without the pins they die with the process that loaded them")
	}
	if stat.Type != bpffsMagic {
		return fail("bpf", "/sys/fs/bpf is not a bpf filesystem",
			"mount -t bpf bpf /sys/fs/bpf; systemd mounts it by default on any supported distribution")
	}
	if err := syscall.Statfs("/sys/fs/cgroup", &stat); err != nil || stat.Type != cgroup2Magic {
		return fail("bpf", "/sys/fs/cgroup is not the unified cgroup2 mount",
			"boot with systemd.unified_cgroup_hierarchy=1; connect-time load "+
				"balancing attaches at the cgroup root (PRD §5.2.5)")
	}

	// The pin directory itself is kanead's to create; what has to be true in
	// advance is that its parent lets that happen.
	if info, err := os.Stat(dpmap.PinRoot); err == nil && info.IsDir() {
		return pass("bpf", "bpffs and cgroup2 are mounted; "+dpmap.PinRoot+" exists")
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		// The pin root is root-owned, so an ordinary user meets EACCES here on
		// a node whose datapath is fine (v1.86). That is a check that did not
		// run, not a node that is broken.
		if deniedByPermission(err) {
			return skip("bpf", "not checked: "+dpmap.PinRoot+" is not readable by this user")
		}
		return fail("bpf", dpmap.PinRoot+": "+err.Error(), "check permissions on "+dpmap.PinRoot)
	}
	parent := filepath.Dir(dpmap.PinRoot)
	if err := syscall.Access(parent, wOK); err != nil {
		// Same distinction one level up (v1.86): kanead runs as root and
		// creates the pin root at startup, so an ordinary user finding the
		// parent unwritable has learned nothing about the node.
		if deniedByPermission(err) {
			return skip("bpf", "not checked: "+parent+" is not writable by this user")
		}
		return fail("bpf", parent+" is not writable: "+err.Error(),
			"kanead runs as root and creates "+dpmap.PinRoot+" at startup")
	}
	return pass("bpf", "bpffs and cgroup2 are mounted; "+dpmap.PinRoot+" is creatable")
}

// wOK is access(2)'s W_OK, which package syscall does not name.
const wOK = 0x2
