package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records commands instead of running them.
type fakeRunner struct {
	mu    sync.Mutex
	calls [][]string
	// failWith maps a command name to the error it should return. A plain
	// "umount" entry does not match "umount -l": the lazy fallback has to be
	// able to succeed where the ordinary one failed.
	failWith map[string]error
	output   []byte
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{failWith: map[string]error{}}
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)

	// Longest key first, so a specific form wins over the bare command name.
	if err, ok := f.failWith[strings.Join(call[:min(2, len(call))], " ")]; ok {
		return f.output, err
	}
	return f.output, f.failWith[name]
}

func (f *fakeRunner) commands() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// lastCommand returns the most recent invocation of a named command.
func (f *fakeRunner) lastCommand(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i][0] == name {
			return f.calls[i]
		}
	}
	return nil
}

func testManager(t *testing.T, runner Runner, secrets SecretResolver) *Manager {
	t.Helper()
	return New(Config{
		Runner:        runner,
		Secrets:       secrets,
		CredentialDir: t.TempDir(),
		CheckTimeout:  200 * time.Millisecond,
		// Nothing is mounted unless a test says so. Tests run on hosts with no
		// /proc/mounts, and the real reader would answer "no" for everything
		// anyway — being explicit keeps that from looking like a passing test.
		MountTable: func(string) (bool, error) { return false, nil },
	})
}

// withMountTable makes the given targets look mounted.
func withMountTable(m *Manager, mounted ...string) {
	set := make(map[string]struct{}, len(mounted))
	for _, t := range mounted {
		set[t] = struct{}{}
	}
	m.mounted = func(path string) (bool, error) {
		_, ok := set[path]
		return ok, nil
	}
}

// fakeSecrets resolves any reference to a fixed credential.
type fakeSecrets struct {
	value string
	err   error
	asked []string
}

func (f *fakeSecrets) Resolve(_ context.Context, ref string) ([]byte, error) {
	f.asked = append(f.asked, ref)
	if f.err != nil {
		return nil, f.err
	}
	return []byte(f.value), nil
}

func TestNFSMountCommand(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, nil)
	target := filepath.Join(t.TempDir(), "shared")

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{Name: "shared-nfs", Type: TypeNFS, Server: "10.0.0.5", Export: "/exports/shop"},
		Target:   target,
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	cmd := runner.lastCommand("mount")
	joined := strings.Join(cmd, " ")
	for _, want := range []string{"-t nfs", "10.0.0.5:/exports/shop", target} {
		if !strings.Contains(joined, want) {
			t.Errorf("command %q missing %q", joined, want)
		}
	}
	// These three are load-bearing, not tuning. `soft` stops a dead server
	// wedging a workload's syscalls forever; `retry=0` stops mount.nfs retrying
	// in the background for two minutes, which otherwise costs the caller its
	// whole timeout on a plainly unreachable server.
	for _, want := range []string{"soft", "retry=0", "timeo="} {
		if !strings.Contains(joined, want) {
			t.Errorf("NFS mount options %q missing %q", joined, want)
		}
	}
}

func TestSMBMountCommandKeepsCredentialsOutOfArgv(t *testing.T) {
	runner := newFakeRunner()
	secrets := &fakeSecrets{value: "alice:hunter2"}
	m := testManager(t, runner, secrets)

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{
			Name: "shared-smb", Type: TypeSMB, Server: "10.0.0.9",
			Share: "media", AuthRef: "secret:storage/smb",
		},
		Target: filepath.Join(t.TempDir(), "media"),
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	joined := strings.Join(runner.lastCommand("mount"), " ")
	// Everything in argv is readable by every process on the host through
	// /proc/<pid>/cmdline, so a password passed as a flag is a published secret.
	if strings.Contains(joined, "hunter2") {
		t.Fatalf("credential leaked into the command line: %q", joined)
	}
	if !strings.Contains(joined, "credentials=") {
		t.Errorf("no credentials file passed: %q", joined)
	}
	if !strings.Contains(joined, "vers=3.0") {
		t.Errorf("SMB version not pinned: %q", joined)
	}
}

// The credential file must not outlive the mount command that reads it.
func TestCredentialFileIsRemovedAfterMounting(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, &fakeSecrets{value: "key:secret"})

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{
			Name: "s3-media", Type: TypeS3, Bucket: "shop-media",
			AuthRef: "secret:storage/s3", Mode: ModeReadOnly,
		},
		Target: filepath.Join(t.TempDir(), "media"),
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	entries, err := os.ReadDir(m.credentialDir)
	if err != nil {
		t.Fatalf("read credential dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("credential files left on disk: %v", entries)
	}
}

func TestS3ModeSelectsTheDriver(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		wantBinary string
	}{
		// mountpoint-s3 is the default and is read-mostly (M0 spike ③).
		{name: "default is mountpoint-s3", mode: "", wantBinary: "mount-s3"},
		{name: "ro is mountpoint-s3", mode: ModeReadOnly, wantBinary: "mount-s3"},
		// s3fs is the only candidate with append and write-at-offset.
		{name: "rw is s3fs", mode: ModeReadWrite, wantBinary: "s3fs"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := newFakeRunner()
			m := testManager(t, runner, &fakeSecrets{value: "key:secret"})

			err := m.Ensure(t.Context(), Request{
				Resource: Resource{
					Name: "s3-media", Type: TypeS3, Bucket: "shop-media",
					Endpoint: "https://s3.example.com", AuthRef: "secret:storage/s3", Mode: tc.mode,
				},
				Target: filepath.Join(t.TempDir(), "media"),
			})
			if err != nil {
				t.Fatalf("Ensure: %v", err)
			}
			if cmd := runner.lastCommand(tc.wantBinary); cmd == nil {
				t.Fatalf("expected %s, got %v", tc.wantBinary, runner.commands())
			}
		})
	}
}

// A driver left to its own defaults retries a dead endpoint for a very long
// time, and every one of those retries is a workload blocked in the kernel.
func TestS3MountSetsExplicitTimeouts(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, &fakeSecrets{value: "key:secret"})

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{
			Name: "s3-media", Type: TypeS3, Bucket: "shop-media",
			AuthRef: "secret:storage/s3", Mode: ModeReadWrite,
		},
		Target: filepath.Join(t.TempDir(), "media"),
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	joined := strings.Join(runner.lastCommand("s3fs"), " ")
	for _, want := range []string{"connect_timeout=", "readwrite_timeout=", "retries="} {
		if !strings.Contains(joined, want) {
			t.Errorf("s3fs command %q does not set %s", joined, want)
		}
	}
	// Without allow_other, root-run containerd cannot traverse a mount made by
	// the unprivileged helper.
	if !strings.Contains(joined, "allow_other") {
		t.Errorf("s3fs command %q does not set allow_other", joined)
	}
}

// A resource that references a secret must refuse to mount rather than mount
// anonymously and silently expose or fail to reach the bucket.
func TestMountRefusesWhenCredentialsCannotBeResolved(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, nil) // no secrets store

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{
			Name: "s3-media", Type: TypeS3, Bucket: "shop-media", AuthRef: "secret:storage/s3",
		},
		Target: filepath.Join(t.TempDir(), "media"),
	})
	if !errors.Is(err, ErrCredentialsUnavailable) {
		t.Fatalf("Ensure = %v, want ErrCredentialsUnavailable", err)
	}
	if len(runner.commands()) != 0 {
		t.Errorf("a mount was attempted without credentials: %v", runner.commands())
	}
}

// Anonymous access is legitimate — a public bucket, an unauthenticated export.
func TestMountWithoutAnAuthRefIsAllowed(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, nil)

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{Name: "public", Type: TypeS3, Bucket: "public-data"},
		Target:   filepath.Join(t.TempDir(), "data"),
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if runner.lastCommand("mount-s3") == nil {
		t.Errorf("no mount attempted: %v", runner.commands())
	}
}

// PRD §8: a mount failure fails the alloc loudly. Returning nil here would let
// a workload start against an empty directory and write data nowhere.
func TestMountFailureIsReported(t *testing.T) {
	runner := newFakeRunner()
	runner.failWith["mount"] = errors.New("exit status 32")
	runner.output = []byte("mount.nfs: Connection timed out")
	m := testManager(t, runner, nil)

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{Name: "shared", Type: TypeNFS, Server: "10.0.0.5", Export: "/x"},
		Target:   filepath.Join(t.TempDir(), "shared"),
	})
	if err == nil {
		t.Fatal("Ensure = nil, want the mount failure")
	}
	// The driver's own diagnostic is what tells an operator whether this is DNS,
	// firewall or permissions, so it must survive into the error.
	if !strings.Contains(err.Error(), "Connection timed out") {
		t.Errorf("error %v does not carry the mount output", err)
	}
}

func TestLocalStorageNeedsNoMount(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, nil)

	err := m.Ensure(t.Context(), Request{
		Resource: Resource{Name: "local-ssd", Type: TypeLocal},
		Target:   t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(runner.commands()) != 0 {
		t.Errorf("local storage ran a mount command: %v", runner.commands())
	}
}

// A plain umount of a wedged FUSE mount blocks exactly like any other access to
// it. Without the lazy fallback, a control plane cannot let go of a dead object
// store — and stops converging.
func TestUnmountFallsBackToLazy(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, nil)
	target := filepath.Join(t.TempDir(), "media")

	// Pretend it is mounted so Release proceeds to unmount.
	m.mounts[target] = &mountState{request: Request{Target: target}}
	// Only the ordinary umount fails; the lazy one is what makes progress.
	runner.failWith["umount "+target] = errors.New("device is busy")

	if err := m.unmount(t.Context(), target); err != nil {
		t.Fatalf("unmount = %v, want the lazy fallback to succeed", err)
	}

	var sawLazy bool
	for _, cmd := range runner.commands() {
		if cmd[0] == "umount" && slices.Contains(cmd, "-l") {
			sawLazy = true
		}
	}
	if !sawLazy {
		t.Fatalf("no lazy unmount attempted: %v", runner.commands())
	}
}

// The core hazard: a stat on a mount whose backing store is gone blocks in the
// kernel and cannot be interrupted. Check must answer on its own timer.
func TestCheckAbandonsAWedgedProbe(t *testing.T) {
	m := testManager(t, newFakeRunner(), nil)
	target := filepath.Join(t.TempDir(), "wedged")
	state := &mountState{request: Request{Target: target}, healthy: true}
	m.mounts[target] = state
	withMountTable(m, target)

	// Simulate a probe already stuck in the kernel.
	state.mu.Lock()
	state.probing = true
	state.mu.Unlock()

	start := time.Now()
	err := m.Check(t.Context(), target)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Check = %v, want ErrTimeout", err)
	}
	// It must not wait for the outstanding probe, and must not start a second
	// one: another blocked syscall tells us nothing we do not already know.
	if elapsed > 100*time.Millisecond {
		t.Errorf("Check waited %v for an outstanding probe", elapsed)
	}
}

// A mount point is an ordinary directory when nothing is mounted on it, so
// stat succeeds either way. Probing with stat alone would report a completely
// failed mount as healthy — the silently-empty-volume failure PRD §8 exists to
// prevent. The directory here exists and is *not* in the mount table.
func TestCheckRejectsAnEmptyMountPoint(t *testing.T) {
	m := testManager(t, newFakeRunner(), nil)
	target := t.TempDir() // exists, so stat succeeds; nothing is mounted on it
	m.mounts[target] = &mountState{request: Request{Target: target}, healthy: true}

	err := m.Check(t.Context(), target)
	if err == nil {
		t.Fatal("Check = nil for a directory with nothing mounted on it")
	}
	if !errors.Is(err, errNotMounted) {
		t.Fatalf("Check = %v, want errNotMounted", err)
	}
	if m.Healthy(target) {
		t.Error("an unmounted path is still recorded as healthy")
	}
}

// s3fs keeps serving ENOENT for objects that are still in the bucket after an
// outage and never recovers on its own (M0 spike ③). A supervisor that only
// reported health would leave a workload reading successful, wrong answers.
func TestSuperviseRemountsAFailedMount(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, nil)

	target := filepath.Join(t.TempDir(), "gone") // nothing mounted: probes fail
	m.mounts[target] = &mountState{
		request: Request{
			Resource: Resource{Name: "s3-media", Type: TypeS3, Bucket: "b"},
			Target:   target,
		},
		healthy: true,
	}

	m.superviseOnce(t.Context())

	if got := m.Remounts(target); got != 1 {
		t.Fatalf("remounts = %d, want 1", got)
	}
	// The recovery is unmount-then-mount, in that order.
	var sawUnmount, sawMount bool
	for _, cmd := range runner.commands() {
		switch cmd[0] {
		case "umount":
			sawUnmount = true
		case "mount-s3":
			if !sawUnmount {
				t.Error("remounted before unmounting")
			}
			sawMount = true
		}
	}
	if !sawMount {
		t.Fatalf("no remount attempted: %v", runner.commands())
	}
}

func TestSuperviseLeavesHealthyMountsAlone(t *testing.T) {
	runner := newFakeRunner()
	m := testManager(t, runner, nil)

	target := t.TempDir() // exists and is mounted, so probes succeed
	m.mounts[target] = &mountState{
		request: Request{Resource: Resource{Name: "shared", Type: TypeNFS}, Target: target},
		healthy: true,
	}
	withMountTable(m, target)

	m.superviseOnce(t.Context())

	if len(runner.commands()) != 0 {
		t.Errorf("a healthy mount was disturbed: %v", runner.commands())
	}
	if got := m.Remounts(target); got != 0 {
		t.Errorf("remounts = %d, want 0", got)
	}
}

func TestRenderCredentials(t *testing.T) {
	aws, err := renderCredentials(awsCredentialFile, []byte("AKIA123:s3cr3t\n"))
	if err != nil {
		t.Fatalf("aws: %v", err)
	}
	for _, want := range []string{"[" + awsProfile + "]", "aws_access_key_id = AKIA123", "aws_secret_access_key = s3cr3t"} {
		if !strings.Contains(string(aws), want) {
			t.Errorf("aws credentials missing %q:\n%s", want, aws)
		}
	}

	smb, err := renderCredentials(smbCredentialFile, []byte("alice:hunter2"))
	if err != nil {
		t.Fatalf("smb: %v", err)
	}
	if !strings.Contains(string(smb), "username=alice") || !strings.Contains(string(smb), "password=hunter2") {
		t.Errorf("smb credentials:\n%s", smb)
	}

	if _, err := renderCredentials(awsCredentialFile, []byte("no-separator")); err == nil {
		t.Error("accepted a credential with no separator")
	}
}

func TestUnescapeMountPath(t *testing.T) {
	tests := map[string]string{
		`/var/lib/kanea`:            "/var/lib/kanea",
		`/mnt/my\040share`:          "/mnt/my share",
		`/mnt/tab\011here`:          "/mnt/tab\there",
		`/mnt/back\134slash`:        `/mnt/back\slash`,
		`/mnt/plain\\not-an-escape`: `/mnt/plain\\not-an-escape`,
	}
	for in, want := range tests {
		if got := unescapeMountPath(in); got != want {
			t.Errorf("unescapeMountPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// A mount command against an unreachable server costs the full mount timeout,
// and the reconcile loop runs every few seconds. Without a backoff, one dead
// NFS server leaves the loop blocked in `mount` most of the time.
func TestMountBacksOffAfterFailures(t *testing.T) {
	runner := newFakeRunner()
	runner.failWith["mount"] = errors.New("exit status 32")

	now := time.Now()
	m := New(Config{
		Runner:        runner,
		CredentialDir: t.TempDir(),
		Now:           func() time.Time { return now },
	})
	req := Request{
		Resource: Resource{Name: "shared", Type: TypeNFS, Server: "192.0.2.99", Export: "/x"},
		Target:   filepath.Join(t.TempDir(), "shared"),
	}

	if err := m.Ensure(t.Context(), req); err == nil {
		t.Fatal("first Ensure = nil, want the mount failure")
	}
	if got := len(runner.commands()); got != 1 {
		t.Fatalf("commands = %d, want 1", got)
	}

	// Immediately after, the attempt is skipped: still an error for the alloc,
	// but no blocking mount command.
	err := m.Ensure(t.Context(), req)
	if err == nil {
		t.Fatal("second Ensure = nil, want it to keep failing")
	}
	if !strings.Contains(err.Error(), "backing off") {
		t.Errorf("error %v does not say it is backing off", err)
	}
	if got := len(runner.commands()); got != 1 {
		t.Fatalf("commands = %d, want the retry to be skipped", got)
	}

	// Once the backoff expires it tries again.
	now = now.Add(time.Minute)
	if err := m.Ensure(t.Context(), req); err == nil {
		t.Fatal("Ensure after the backoff = nil, want another attempt")
	}
	if got := len(runner.commands()); got != 2 {
		t.Fatalf("commands = %d, want a retry after the backoff", got)
	}
}

// A mount that starts working must clear its failure history, or the backoff
// would keep growing across unrelated outages.
func TestMountBackoffResetsOnSuccess(t *testing.T) {
	runner := newFakeRunner()
	runner.failWith["mount"] = errors.New("exit status 32")

	now := time.Now()
	m := New(Config{
		Runner:        runner,
		CredentialDir: t.TempDir(),
		Now:           func() time.Time { return now },
	})
	req := Request{
		Resource: Resource{Name: "shared", Type: TypeNFS, Server: "10.0.0.5", Export: "/x"},
		Target:   filepath.Join(t.TempDir(), "shared"),
	}

	if err := m.Ensure(t.Context(), req); err == nil {
		t.Fatal("want the first attempt to fail")
	}

	delete(runner.failWith, "mount")
	now = now.Add(time.Minute)
	if err := m.Ensure(t.Context(), req); err != nil {
		t.Fatalf("Ensure after recovery = %v, want nil", err)
	}

	// The next failure should start from the shortest delay again.
	runner.failWith["mount"] = errors.New("exit status 32")
	if err := m.Ensure(t.Context(), req); err == nil {
		t.Fatal("want the later attempt to fail")
	}
	if got := len(runner.commands()); got != 3 {
		t.Fatalf("commands = %d, want the attempt not to have been skipped", got)
	}
}

// The counterpart to TestCheckRejectsAnEmptyMountPoint: a path that *is* in the
// mount table and answers a stat is healthy.
func TestCheckAcceptsARealMount(t *testing.T) {
	m := testManager(t, newFakeRunner(), nil)
	target := t.TempDir()
	m.mounts[target] = &mountState{request: Request{Target: target}}
	withMountTable(m, target)

	if err := m.Check(t.Context(), target); err != nil {
		t.Fatalf("Check = %v, want nil", err)
	}
	if !m.Healthy(target) {
		t.Error("mount not recorded as healthy")
	}
}

// A probe result must never clear the reason a mount is backing off — otherwise
// the operator-facing error degrades to "backing off after 1 failures: <nil>".
func TestProbeDoesNotEraseTheMountFailure(t *testing.T) {
	runner := newFakeRunner()
	runner.failWith["mount"] = errors.New("exit status 32")

	now := time.Now()
	m := New(Config{
		Runner: runner, CredentialDir: t.TempDir(),
		Now:        func() time.Time { return now },
		MountTable: func(string) (bool, error) { return false, nil },
	})
	target := filepath.Join(t.TempDir(), "shared")
	req := Request{
		Resource: Resource{Name: "shared", Type: TypeNFS, Server: "192.0.2.99", Export: "/x"},
		Target:   target,
	}

	if err := m.Ensure(t.Context(), req); err == nil {
		t.Fatal("want the mount to fail")
	}
	// A probe runs in between, as the supervisor would.
	_ = m.Check(t.Context(), target)

	err := m.Ensure(t.Context(), req)
	if err == nil {
		t.Fatal("want the backoff to keep failing")
	}
	if strings.Contains(err.Error(), "<nil>") {
		t.Fatalf("the mount failure was lost: %v", err)
	}
	if !strings.Contains(err.Error(), "exit status 32") {
		t.Errorf("error %v does not carry the original mount failure", err)
	}
}
