package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/m18h/kanea/internal/notify"
)

// slogLogger is an alias so Config can name the type before slog is imported
// by every file in the package.
type slogLogger = slog.Logger

// Manager establishes, supervises and releases volume mounts.
//
// It is safe for concurrent use, and every mount is guarded by its own lock so
// a wedged mount cannot block operations on any other one, which matters,
// because "wedged" is the normal failure mode here, not an exotic one.
type Manager struct {
	runner        Runner
	secrets       SecretResolver
	credentialDir string
	log           *slog.Logger

	mountTimeout   time.Duration
	unmountTimeout time.Duration
	checkTimeout   time.Duration
	now            func() time.Time
	// mounted reports whether a path is in the kernel's mount table. It is a
	// field so tests can model a mount table on a host that has none.
	mounted   func(string) (bool, error)
	hostPaths HostPathPolicy
	// emit publishes volume.* events (§11). Nil disables them, as it does for
	// the reconciler.
	emit func(notify.Event)

	mu     sync.Mutex
	mounts map[mountPath]*mountState
}

// mountState tracks one established mount.
type mountState struct {
	mu      sync.Mutex
	request Request
	// healthy is the last probe verdict.
	healthy bool
	// probing guards against stacking probes on a wedged mount. A probe that
	// times out leaves a goroutine stuck in the kernel; starting another one
	// every interval would leak a goroutine per interval until the mount
	// recovers, which on a dead object store is minutes.
	probing bool
	// remounts counts recoveries, for the event log.
	remounts int
	// announcedFailure records that a volume.mount_failed has been sent and
	// not yet cleared. It is what makes the pair fire on transitions: a wedged
	// mount is probed every 30 s and a failing one is retried every pass, so
	// without it an outage would be one notification per probe. It also keeps
	// the *first* successful mount silent: starting false means there is no
	// failure to recover from.
	announcedFailure bool
	// lastProbeErr is why the most recent health probe failed.
	lastProbeErr error
	// lastMountErr is why the most recent mount attempt failed. It is kept
	// separate from the probe result so a probe can never clear the reason a
	// mount is backing off.
	lastMountErr error
	// failures and nextAttemptAt back off repeated mount attempts. A mount
	// command against an unreachable server costs the full mount timeout, and
	// the reconcile loop runs every few seconds: without a backoff a single
	// dead NFS server would leave the loop blocked in `mount` most of the time.
	//
	// The backoff deliberately resets on a daemon restart (PRD v1.37): the
	// kernel mount table, not this struct, is the ground truth Ensure consults
	// first, mounts are keyed by paths whose allocs may not exist any more,
	// and a restart is legitimately a moment the operator may have fixed the
	// server. The post-restart cost is bounded: one honest mount attempt per
	// distinct target, serialized per mount, before the schedule re-arms.
	failures      int
	nextAttemptAt time.Time
}

// mountBackoff is the delay schedule after a failed mount. The last entry
// repeats, so a permanently unreachable server settles at one attempt a minute
// instead of one per reconcile pass.
var mountBackoff = []time.Duration{
	5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute,
}

// delayAfter returns the backoff before attempt n (1-based).
func delayAfter(n int) time.Duration {
	if n <= 0 {
		return 0
	}
	if n > len(mountBackoff) {
		n = len(mountBackoff)
	}
	return mountBackoff[n-1]
}

// New builds a Manager.
func New(cfg Config) *Manager {
	if cfg.Runner == nil {
		cfg.Runner = execRunner{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.MountTimeout <= 0 {
		cfg.MountTimeout = DefaultMountTimeout
	}
	if cfg.UnmountTimeout <= 0 {
		cfg.UnmountTimeout = DefaultUnmountTimeout
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = DefaultCheckTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MountTable == nil {
		cfg.MountTable = isMountPoint
	}
	return &Manager{
		runner:         cfg.Runner,
		secrets:        cfg.Secrets,
		credentialDir:  cfg.CredentialDir,
		log:            cfg.Logger,
		mountTimeout:   cfg.MountTimeout,
		unmountTimeout: cfg.UnmountTimeout,
		checkTimeout:   cfg.CheckTimeout,
		now:            cfg.Now,
		mounted:        cfg.MountTable,
		hostPaths:      cfg.HostPaths,
		emit:           cfg.Emit,
		mounts:         map[mountPath]*mountState{},
	}
}

// Ensure establishes a mount if it is not already present. It is idempotent:
// the reconciler calls it before every alloc that uses the volume.
func (m *Manager) Ensure(ctx context.Context, req Request) error {
	if !req.Resource.NeedsMount() {
		// A local volume is a directory; the reconciler already creates it.
		return nil
	}
	if req.Target == "" {
		return fmt.Errorf("storage: %s has no target path", req.Resource.Name)
	}

	state := m.stateFor(req)
	state.mu.Lock()
	defer state.mu.Unlock()

	mounted, err := m.mounted(req.Target)
	if err != nil {
		return err
	}
	if mounted {
		state.healthy = true
		state.failures = 0
		return nil
	}

	// Fail fast while backing off. The alloc still does not start (which is
	// the point) but the reconcile pass is not spent blocked in a mount
	// command that is going to time out again.
	if state.failures > 0 && m.now().Before(state.nextAttemptAt) {
		return fmt.Errorf("mount %s at %s is backing off after %d failures: %w",
			req.Resource.Name, req.Target, state.failures, state.lastMountErr)
	}
	return m.mount(ctx, state, req)
}

// mount runs the mount command. The caller holds the mount's lock.
func (m *Manager) mount(ctx context.Context, state *mountState, req Request) error {
	if err := os.MkdirAll(req.Target, 0o750); err != nil {
		return fmt.Errorf("mount point %s: %w", req.Target, err)
	}

	name, args, cleanup, err := m.mountCommand(ctx, req)
	if err != nil {
		return err
	}
	// The credential file lives only as long as the mount command needs it.
	// Both drivers read it at startup; leaving it on disk afterwards would be a
	// secret at rest for no reason.
	defer cleanup()

	ctx, cancel := context.WithTimeout(ctx, m.mountTimeout)
	defer cancel()

	out, err := m.runner.Run(ctx, name, args...)
	if err != nil {
		state.healthy = false
		// Mount failures are loud (PRD §8): the alloc that needs this volume
		// must not start with a missing or silently-empty directory.
		failure := fmt.Errorf("mount %s at %s: %w (%s)",
			req.Resource.Name, req.Target, err, trimOutput(out))
		state.lastMountErr = failure
		state.failures++
		state.nextAttemptAt = m.now().Add(delayAfter(state.failures))
		m.announceFailure(state, req, failure)
		return failure
	}

	state.healthy = true
	state.lastMountErr = nil
	state.lastProbeErr = nil
	state.failures = 0
	m.log.Info("mounted volume",
		"storage", req.Resource.Name, "type", req.Resource.Type, "target", req.Target)
	m.announceRecovery(state, req)
	return nil
}

// announceFailure emits volume.mount_failed the first time a mount goes bad,
// and stays quiet until it recovers.
//
// The caller holds the mount's own lock. Emitting under it is safe by
// constraint #8 (Publish never blocks and never returns an error) and the
// lock is per mount, so even a misbehaving emitter could not stall a different
// volume.
func (m *Manager) announceFailure(state *mountState, req Request, cause error) {
	if state.announcedFailure {
		return
	}
	state.announcedFailure = true
	if m.emit == nil {
		return
	}
	m.emit(notify.NewEvent(notify.EventVolumeMountFailed, "", "",
		fmt.Sprintf("volume mount %s is not available: %v", req.Resource.Name, cause),
		m.now()).WithDetail(req.Target))
}

// announceRecovery emits volume.mount_recovered, but only for a mount that had
// actually been announced as failed. A first successful mount is not a
// recovery, and reporting it as one would make every deploy look like an
// incident that resolved itself.
func (m *Manager) announceRecovery(state *mountState, req Request) {
	if !state.announcedFailure {
		return
	}
	state.announcedFailure = false
	if m.emit == nil {
		return
	}
	m.emit(notify.NewEvent(notify.EventVolumeMountRecovered, "", "",
		fmt.Sprintf("volume mount %s is available again", req.Resource.Name),
		m.now()).WithDetail(req.Target))
}

// Release unmounts and forgets a mount. Missing is success.
func (m *Manager) Release(ctx context.Context, target string) error {
	m.mu.Lock()
	state, tracked := m.mounts[target]
	delete(m.mounts, target)
	m.mu.Unlock()

	if tracked {
		state.mu.Lock()
		defer state.mu.Unlock()
	}

	mounted, err := m.mounted(target)
	if err != nil {
		return err
	}
	if !mounted {
		return nil
	}
	return m.unmount(ctx, target)
}

// unmount detaches a mount, falling back to a lazy detach.
//
// The fallback is not optional. A plain umount of a wedged FUSE mount blocks
// exactly like any other access to it, and a control plane that cannot let go
// of a dead object store is a control plane that stops converging. `umount -l`
// detaches the mount from the tree immediately and lets the kernel clean up
// whenever the driver finally gives up.
func (m *Manager) unmount(ctx context.Context, target string) error {
	ctx, cancel := context.WithTimeout(ctx, m.unmountTimeout)
	defer cancel()

	out, err := m.runner.Run(ctx, "umount", target)
	if err == nil {
		m.log.Info("unmounted volume", "target", target)
		return nil
	}
	firstErr := fmt.Errorf("umount %s: %w (%s)", target, err, trimOutput(out))

	lazyCtx, lazyCancel := context.WithTimeout(context.WithoutCancel(ctx), m.unmountTimeout)
	defer lazyCancel()

	if out, lazyErr := m.runner.Run(lazyCtx, "umount", "-l", target); lazyErr != nil {
		return errors.Join(firstErr, fmt.Errorf("lazy umount %s: %w (%s)", target, lazyErr, trimOutput(out)))
	}
	m.log.Warn("volume needed a lazy unmount; the backing store is probably unreachable",
		"target", target, "error", firstErr)
	return nil
}

// errNotMounted marks a target that has no mount on it at all.
var errNotMounted = errors.New("storage: nothing is mounted at this path")

// ResolveHost checks a host volume against the operator's allowlist and returns
// the directory to bind-mount (R15).
//
// It lives on the Manager rather than being a free function because the
// allowlist is node configuration, and the Manager is where node configuration
// already lives. A caller that has one of these has, by construction, been
// given the operator's policy rather than inventing one.
//
// create carries the spec's `create = true` (R15, v1.69) through to the policy,
// which decides whether a missing directory may be made, and refuses outside
// an allowed prefix before making anything.
func (m *Manager) ResolveHost(path string, create bool) (string, error) {
	return m.hostPaths.ResolveOrCreate(path, create)
}

// HostStagingDir is where host volumes are staged for a race-free hand to
// runc: one bind-mounted, fd-pinned directory per alloc per volume, under a
// root-owned tree (K-20).
const HostStagingDir = "/run/kanea/host-volumes"

// StageHost pins the checked directory and bind-mounts it under the staging
// tree, returning the staging path to hand to the runtime (K-20). The mount
// source is /proc/self/fd/N of an openat2-pinned handle: the object the
// allowlist was checked against is the object mounted, and a workload that
// could rename the checked path between Resolve and the container's mount -
// the race the string answer left open - finds the race already lost.
//
// A retry re-stages over a stale bind (unmount, then mount): a create that
// failed after staging must not inherit the previous attempt's.
//
// Off linux there is no runc and no race to close (dev mode): the resolved
// path itself comes back, unchanged.
func (m *Manager) StageHost(allocID, volume, resolved string) (string, error) {
	if !stagingSupported {
		return resolved, nil
	}
	target := filepath.Join(HostStagingDir, allocID, volume)
	// Stale state from a crashed attempt is replaced, never stacked on.
	if err := unstagePath(m.mounted, target); err != nil {
		return "", err
	}
	if err := pinAndBind(resolved, target, m.hostPaths.Allowed()); err != nil {
		return "", err
	}
	return target, nil
}

// UnstageHost releases every staged bind one alloc held. Absent is success:
// teardown runs on paths where part of it already happened.
func (m *Manager) UnstageHost(allocID string) error {
	if !stagingSupported {
		return nil
	}
	base := filepath.Join(HostStagingDir, allocID)
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("list staging for %s: %w", allocID, err)
	}
	var errs []error
	for _, e := range entries {
		if err := unstagePath(m.mounted, filepath.Join(base, e.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(base); err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("remove staging base %s: %w", base, err))
	}
	return errors.Join(errs...)
}

// Prune releases every tracked mount whose target is not in keep.
func (m *Manager) Prune(ctx context.Context, keep map[string]struct{}) error {
	var errs []error
	for target := range m.snapshot() {
		if _, wanted := keep[target]; wanted {
			continue
		}
		if err := m.Release(ctx, target); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Check probes one mount and reports whether it is answering.
//
// The probe runs on a goroutine this function is willing to abandon. That is
// the whole point: a stat on a mount whose backing store has gone away blocks
// in the kernel for 40 s to over 2 minutes and cannot be interrupted, so
// waiting for it *is* the outage. Abandoning the goroutine leaks it until the
// driver's own timeout fires, which is why `probing` stops another one being
// started in the meantime.
func (m *Manager) Check(ctx context.Context, target string) error {
	state := m.lookup(target)
	if state == nil {
		return fmt.Errorf("storage: %s is not a tracked mount", target)
	}

	// The mount table first, and it is not an optimisation.
	//
	// A mount point is an ordinary directory when nothing is mounted on it, so
	// os.Stat succeeds just the same: it cannot tell "mounted and serving"
	// from "empty directory where a volume should be". Probing with stat alone
	// would report a completely failed mount as healthy, which is precisely the
	// silently-empty-volume failure PRD §8 exists to prevent. Reading
	// /proc/mounts is cheap and never blocks.
	mounted, err := m.mounted(target)
	if err != nil {
		return err
	}
	if !mounted {
		state.mu.Lock()
		state.healthy = false
		state.lastProbeErr = errNotMounted
		state.mu.Unlock()
		return fmt.Errorf("%w: %s", errNotMounted, target)
	}

	state.mu.Lock()
	if state.probing {
		state.mu.Unlock()
		// A probe is already stuck on this mount. Reporting the previous
		// verdict is honest (we know no more than we did) and starting a
		// second blocked syscall would tell us nothing new.
		return fmt.Errorf("%w: a probe of %s is still outstanding", ErrTimeout, target)
	}
	state.probing = true
	state.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		_, err := os.Stat(target)
		done <- err

		state.mu.Lock()
		state.probing = false
		state.mu.Unlock()
	}()

	timer := time.NewTimer(m.checkTimeout)
	defer timer.Stop()

	select {
	case err := <-done:
		state.mu.Lock()
		state.healthy = err == nil
		state.lastProbeErr = err
		state.mu.Unlock()
		if err != nil {
			return fmt.Errorf("probe %s: %w", target, err)
		}
		return nil

	case <-timer.C:
		state.mu.Lock()
		state.healthy = false
		state.lastProbeErr = ErrTimeout
		state.mu.Unlock()
		return fmt.Errorf("%w: %s did not answer within %v", ErrTimeout, target, m.checkTimeout)

	case <-ctx.Done():
		return ctx.Err()
	}
}

// Supervise probes every tracked mount and remounts the ones that have failed,
// until the context is cancelled.
//
// Remounting is mandatory rather than defensive. After an object-store outage
// s3fs keeps serving ENOENT for objects that are still in the bucket and never
// recovers on its own (M0 spike ③): the mount is stale, not the data. Nothing
// short of a remount fixes it, so a supervisor that only reported health would
// leave a workload reading successful, empty, wrong answers.
func (m *Manager) Supervise(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultCheckInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.superviseOnce(ctx)
		}
	}
}

func (m *Manager) superviseOnce(ctx context.Context) {
	for target, state := range m.snapshot() {
		err := m.Check(ctx, target)
		if err == nil {
			continue
		}
		if errors.Is(err, context.Canceled) {
			return
		}
		m.log.Warn("volume mount is not answering", "target", target, "error", err)

		state.mu.Lock()
		req := state.request
		// A probe failure is the other way a mount becomes unavailable, and it
		// is the one the supervisor exists for: after an object-store outage
		// s3fs keeps serving ENOENT for objects that are intact. Announcing it
		// here means the remount below reports as a recovery.
		m.announceFailure(state, req, err)
		state.mu.Unlock()

		if err := m.remount(ctx, state, req); err != nil {
			m.log.Error("remount failed", "storage", req.Resource.Name, "target", target, "error", err)
			continue
		}
		m.log.Info("remounted volume after a failed probe",
			"storage", req.Resource.Name, "target", target)
	}
}

// remount detaches and re-establishes a mount.
func (m *Manager) remount(ctx context.Context, state *mountState, req Request) error {
	state.mu.Lock()
	defer state.mu.Unlock()

	// Unmount first, ignoring the result: the mount is already failing, and the
	// lazy fallback inside unmount is what makes progress possible at all.
	if err := m.unmount(ctx, req.Target); err != nil {
		m.log.Warn("unmount before remount did not succeed cleanly",
			"target", req.Target, "error", err)
	}
	if err := m.mount(ctx, state, req); err != nil {
		return err
	}
	state.remounts++
	return nil
}

// Healthy reports the last known verdict for a mount.
func (m *Manager) Healthy(target string) bool {
	state := m.lookup(target)
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.healthy
}

// Remounts reports how many times a mount has been recovered.
func (m *Manager) Remounts(target string) int {
	state := m.lookup(target)
	if state == nil {
		return 0
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.remounts
}

func (m *Manager) stateFor(req Request) *mountState {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.mounts[req.Target]
	if !ok {
		state = &mountState{request: req}
		m.mounts[req.Target] = state
		return state
	}
	state.request = req
	return state
}

func (m *Manager) lookup(target string) *mountState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mounts[target]
}

func (m *Manager) snapshot() map[mountPath]*mountState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[mountPath]*mountState, len(m.mounts))
	for k, v := range m.mounts {
		out[k] = v
	}
	return out
}

// maxOutputChars keeps a command's diagnostics readable in one log line.
const maxOutputChars = 200

// trimOutput bounds and flattens a command's output for logging.
func trimOutput(out []byte) string {
	s := string(out)
	if len(s) > maxOutputChars {
		s = s[:maxOutputChars] + "…"
	}
	return sanitizeOneLine(s)
}

func sanitizeOneLine(s string) string {
	var b []rune
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		b = append(b, r)
	}
	return string(b)
}
