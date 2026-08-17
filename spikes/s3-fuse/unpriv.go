package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"
)

// mountUser is created by provision-vm.sh. PRD §8 requires FUSE mounts to run
// "under a dedicated, unprivileged helper process per mount", so the mount must
// work without root, and the mount must still be usable by root-run containerd.
const mountUser = "kanea-s3"

// runUnpriv checks whether each driver can be mounted by an unprivileged user.
// It is a separate phase because it must NOT reuse the root-owned mounts: it
// mounts and unmounts entirely as `kanea-s3`.
func runUnpriv(ctx context.Context, d *driver) error {
	fmt.Printf("\n── %s: unprivileged mount (PRD §8 helper process) ──\n", d.Name)

	u, err := user.Lookup(mountUser)
	if err != nil {
		check(d.Name+": unprivileged mount", false,
			fmt.Sprintf("user %s missing; rerun provision-vm.sh", mountUser))
		return nil
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	// Root must not hold the mount point while the helper takes it over.
	if err := d.unmount(); err != nil {
		return err
	}
	mnt := d.Mount + "-unpriv"
	if err := os.MkdirAll(mnt, 0o755); err != nil {
		return err
	}
	if err := os.Chown(mnt, uid, gid); err != nil {
		return err
	}
	defer func() {
		_ = exec.Command("fusermount3", "-u", mnt).Run()
		_ = os.Remove(mnt)
	}()

	unpriv := *d
	unpriv.Mount = mnt
	argv := unpriv.args(&unpriv)
	// The root credential files are 0600 root; the helper gets its own copies.
	for i, a := range argv {
		argv[i] = strings.ReplaceAll(a,
			"passwd_file=/etc/kanea-spike-s3fs.passwd",
			"passwd_file=/etc/kanea-spike-s3fs-unpriv.passwd")
	}

	// sudo -u drops privileges the way a systemd User= helper unit would.
	sudoArgs := append([]string{"-n", "-u", mountUser, "-H"}, argv...)
	out, mErr := exec.Command("sudo", sudoArgs...).CombinedOutput() // #nosec G204; spike
	mounted := false
	if mErr == nil {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if unpriv.mounted() {
				mounted = true
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	detail := strings.TrimSpace(string(bytes.TrimSpace(out)))
	if len(detail) > 90 {
		detail = detail[:90] + "…"
	}
	check(d.Name+": mounts as an unprivileged user", mounted, detail)
	if !mounted {
		return nil
	}

	// The helper is unprivileged; the daemon process must be owned by it.
	owner, _ := exec.Command("sh", "-c",
		fmt.Sprintf("ps -o user= -p $(findmnt -n -o SOURCE %s >/dev/null 2>&1; pgrep -f %q | head -1)", mnt, mnt)).Output()
	check(d.Name+": FUSE daemon runs as the helper user",
		strings.Contains(string(owner), mountUser),
		fmt.Sprintf("daemon owner=%q", strings.TrimSpace(string(owner))))

	// Root (i.e. containerd, which binds the mount into an alloc) must still be
	// able to traverse it: this is what allow_other + user_allow_other buys.
	rootReadable := false
	testFile := mnt + "/unpriv.txt"
	werr := exec.Command("sudo", "-n", "-u", mountUser, "sh", "-c",
		fmt.Sprintf("echo unprivileged-write > %q", testFile)).Run() // #nosec G204; spike
	if werr == nil {
		b, rerr := os.ReadFile(testFile) // this process is root
		rootReadable = rerr == nil && strings.Contains(string(b), "unprivileged-write")
	}
	check(d.Name+": root can read through the unprivileged mount (allow_other)",
		rootReadable, fmt.Sprintf("write as %s: %v", mountUser, werr))

	return nil
}
