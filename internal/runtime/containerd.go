package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/pkg/cio"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/errdefs"
	"github.com/containerd/typeurl/v2"

	apievents "github.com/containerd/containerd/api/events"
)

// Config configures the containerd driver.
type Config struct {
	// Socket is containerd's gRPC socket. Defaults to the standard path.
	Socket string
	// Logger receives driver events. Defaults to a discard logger.
	Logger *slog.Logger
	// DefaultGrace bounds SIGTERM before SIGKILL when Stop is called without
	// one. Defaults to 10s.
	DefaultGrace time.Duration
}

// DefaultSocket is the containerd `kanea install` provisions (PRD §5.2.12).
//
// Deliberately not /run/containerd/containerd.sock, which belongs to whatever
// else on the node is using containerd. Kanea installs its own daemon at a
// pinned version on its own socket, so a node that ran Docker yesterday runs
// it tomorrow; `--containerd /run/containerd/containerd.sock` adopts an
// existing one for an operator who wants a single runtime on the box.
const DefaultSocket = "/run/kanea/containerd.sock"

type containerdDriver struct {
	client *containerd.Client
	log    *slog.Logger
	grace  time.Duration
}

// New dials containerd and returns the driver.
func New(cfg Config) (Driver, error) {
	if cfg.Socket == "" {
		cfg.Socket = DefaultSocket
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.DefaultGrace <= 0 {
		cfg.DefaultGrace = 10 * time.Second
	}

	client, err := containerd.New(cfg.Socket)
	if err != nil {
		return nil, fmt.Errorf("dial containerd at %s: %w", cfg.Socket, err)
	}
	return &containerdDriver{client: client, log: cfg.Logger, grace: cfg.DefaultGrace}, nil
}

func (d *containerdDriver) Close() error { return d.client.Close() }

// scope binds the context to the project's containerd namespace. Every call
// goes through it: a missing namespace would silently address another
// project's containers.
func scope(ctx context.Context, project string) context.Context {
	return namespaces.WithNamespace(ctx, Namespace(project))
}

func (d *containerdDriver) EnsureImage(ctx context.Context, img ImageRef) (string, error) {
	ctx = scope(ctx, img.Project)

	ref, err := NormalizeRef(img.Ref)
	if err != nil {
		return "", err
	}

	if existing, err := d.client.GetImage(ctx, ref); err == nil {
		return existing.Target().Digest.String(), nil
	} else if !errdefs.IsNotFound(err) {
		return "", fmt.Errorf("look up image %s: %w", ref, err)
	}

	opts := []containerd.RemoteOpt{containerd.WithPullUnpack}
	if len(img.Auth) > 0 {
		resolver, err := resolverFor(img.Auth)
		if err != nil {
			return "", err
		}
		opts = append(opts, containerd.WithResolver(resolver))
	}

	d.log.Info("pulling image", "project", img.Project, "ref", ref,
		"authenticated", len(img.Auth) > 0)
	pulled, err := d.client.Pull(ctx, ref, opts...)
	if err != nil {
		return "", fmt.Errorf("pull %s: %w", ref, err)
	}
	return pulled.Target().Digest.String(), nil
}

// ResolveRemote asks the registry what a reference points at *now*, without
// pulling it (PRD §6.2 R19).
//
// This is the whole reason auto-update needs a method of its own. EnsureImage
// answers from the local content store whenever the image is already there —
// which is correct for starting an alloc and useless for noticing that a tag
// has moved, since the answer is by construction the digest that is already
// running. Only a manifest is fetched here, not the layers.
func (d *containerdDriver) ResolveRemote(ctx context.Context, img ImageRef) (string, error) {
	ref, err := NormalizeRef(img.Ref)
	if err != nil {
		return "", err
	}
	resolver, err := resolverFor(img.Auth)
	if err != nil {
		return "", err
	}
	_, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", ref, err)
	}
	return desc.Digest.String(), nil
}

func (d *containerdDriver) Create(ctx context.Context, spec AllocSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	ctx = scope(ctx, spec.Project)

	// The same expansion EnsureImage used, or the lookup misses what the pull
	// stored under the qualified name.
	ref, err := NormalizeRef(spec.Image)
	if err != nil {
		return err
	}
	img, err := d.client.GetImage(ctx, ref)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return fmt.Errorf("image %s not pulled: %w", ref, err)
		}
		return fmt.Errorf("look up image %s: %w", ref, err)
	}

	// Image config first, then our options: hardening and limits must win over
	// anything the image asks for.
	opts := append([]oci.SpecOpts{oci.WithImageConfig(img)}, specOpts(spec)...)

	newOpts := []containerd.NewContainerOpts{
		containerd.WithImage(img),
		containerd.WithNewSnapshot(snapshotID(spec.ID), img),
		containerd.WithNewSpec(opts...),
		containerd.WithContainerLabels(labels(spec)),
	}
	newOpts = append(newOpts, runtimeOpts(spec)...)

	container, err := d.client.NewContainer(ctx, spec.ID, newOpts...)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return fmt.Errorf("%w: %s", ErrAlreadyExists, spec.ID)
		}
		return fmt.Errorf("create container %s: %w", spec.ID, err)
	}

	if _, err := container.NewTask(ctx, d.io(spec)); err != nil {
		// Roll back: a container with no task is invisible to Status and would
		// leak its snapshot.
		return errors.Join(
			fmt.Errorf("create task %s: %w", spec.ID, err),
			container.Delete(ctx, containerd.WithSnapshotCleanup),
		)
	}
	return nil
}

// runtimeOpts selects the containerd runtime for a spec.
//
// Empty for an empty Runtime: containerd's client falls back to its compiled
// default (the runc shim), and that default is containerd's to own — only a
// departure from it is written down (PRD v1.39, §6.2 R25). Validate has
// already closed the set, so what reaches here is the wasmtime shim's name.
func runtimeOpts(spec AllocSpec) []containerd.NewContainerOpts {
	if spec.Runtime == "" {
		return nil
	}
	return []containerd.NewContainerOpts{containerd.WithRuntime(spec.Runtime, nil)}
}

// ImageInfo describes an image as this node's content store holds it.
type ImageInfo struct {
	// Digest is the image's manifest digest.
	Digest string
	// SizeBytes is the compressed content size — what the Functions page
	// shows as the artifact size (PRD §12.2).
	SizeBytes int64
}

// ImageInfo reports a locally present image; ErrNotFound if it was never
// pulled. It is deliberately not part of the Driver interface: the reconciler
// has no use for it, and the API consumer defines its own slice (interfaces at
// the consumer).
func (d *containerdDriver) ImageInfo(ctx context.Context, project, ref string) (ImageInfo, error) {
	ctx = scope(ctx, project)
	nref, err := NormalizeRef(ref)
	if err != nil {
		return ImageInfo{}, err
	}
	img, err := d.client.GetImage(ctx, nref)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return ImageInfo{}, fmt.Errorf("%w: image %s", ErrNotFound, nref)
		}
		return ImageInfo{}, fmt.Errorf("look up image %s: %w", nref, err)
	}
	size, err := img.Size(ctx)
	if err != nil {
		return ImageInfo{}, fmt.Errorf("size of %s: %w", nref, err)
	}
	return ImageInfo{Digest: img.Target().Digest.String(), SizeBytes: size}, nil
}

// io sends the task's stdout and stderr to the alloc's log file. The full
// non-blocking drain with drop counters (PRD §17) belongs in the log pipeline;
// what matters here is that the shim owns the write, so a slow reader on our
// side can never block the workload.
func (d *containerdDriver) io(spec AllocSpec) cio.Creator {
	if spec.LogPath == "" {
		return cio.NullIO
	}
	if err := os.MkdirAll(filepath.Dir(spec.LogPath), 0o750); err != nil {
		d.log.Warn("cannot create log directory; discarding task output",
			"alloc", spec.ID, "path", spec.LogPath, "error", err)
		return cio.NullIO
	}
	return cio.LogFile(spec.LogPath)
}

func (d *containerdDriver) Start(ctx context.Context, project, id string) error {
	ctx = scope(ctx, project)
	task, err := d.task(ctx, id)
	if err != nil {
		return err
	}
	if err := task.Start(ctx); err != nil {
		return fmt.Errorf("start %s: %w", id, err)
	}
	return nil
}

func (d *containerdDriver) Status(ctx context.Context, project, id string) (Status, error) {
	ctx = scope(ctx, project)

	container, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return Status{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return Status{}, fmt.Errorf("load %s: %w", id, err)
	}
	return d.statusOf(ctx, container)
}

func (d *containerdDriver) statusOf(ctx context.Context, container containerd.Container) (Status, error) {
	out := Status{ID: container.ID(), State: StateUnknown}
	if info, err := container.Info(ctx); err == nil {
		out.Image = info.Image
	}

	task, err := container.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			// Container without a task: created then torn down, or mid-restart.
			out.State = StateStopped
			return out, nil
		}
		return out, fmt.Errorf("task of %s: %w", container.ID(), err)
	}
	out.PID = task.Pid()

	status, err := task.Status(ctx)
	if err != nil {
		return out, fmt.Errorf("status of %s: %w", container.ID(), err)
	}
	out.State = mapState(status.Status)
	out.ExitCode = status.ExitStatus
	out.ExitedAt = status.ExitTime
	return out, nil
}

func (d *containerdDriver) List(ctx context.Context, project string) ([]Status, error) {
	ctx = scope(ctx, project)

	containers, err := d.client.Containers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list containers in %s: %w", project, err)
	}
	out := make([]Status, 0, len(containers))
	for _, c := range containers {
		status, err := d.statusOf(ctx, c)
		if err != nil {
			// One broken alloc must not hide the rest: report it as unknown.
			d.log.Warn("cannot read alloc status", "alloc", c.ID(), "error", err)
			status = Status{ID: c.ID(), State: StateUnknown}
		}
		out = append(out, status)
	}
	return out, nil
}

// Stop asks politely, then insists. A workload that ignores SIGTERM must not
// hold up a deploy indefinitely.
func (d *containerdDriver) Stop(ctx context.Context, project, id string, grace time.Duration) error {
	if grace <= 0 {
		grace = d.grace
	}
	ctx = scope(ctx, project)

	task, err := d.task(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil // already gone: stopping is idempotent
		}
		return err
	}

	exited, err := task.Wait(ctx)
	if err != nil {
		return fmt.Errorf("wait %s: %w", id, err)
	}
	if err := task.Kill(ctx, syscall.SIGTERM); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("SIGTERM %s: %w", id, err)
	}

	select {
	case <-exited:
		return nil
	case <-time.After(grace):
		d.log.Warn("alloc ignored SIGTERM; sending SIGKILL", "alloc", id, "grace", grace)
		if err := task.Kill(ctx, syscall.SIGKILL); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("SIGKILL %s: %w", id, err)
		}
		select {
		case <-exited:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *containerdDriver) Remove(ctx context.Context, project, id string) error {
	ctx = scope(ctx, project)

	container, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil // idempotent
		}
		return fmt.Errorf("load %s: %w", id, err)
	}
	if task, err := container.Task(ctx, nil); err == nil {
		if _, err := task.Delete(ctx, containerd.WithProcessKill); err != nil && !errdefs.IsNotFound(err) {
			return fmt.Errorf("delete task %s: %w", id, err)
		}
	} else if !errdefs.IsNotFound(err) {
		return fmt.Errorf("task of %s: %w", id, err)
	}
	if err := container.Delete(ctx, containerd.WithSnapshotCleanup); err != nil && !errdefs.IsNotFound(err) {
		return fmt.Errorf("delete container %s: %w", id, err)
	}
	return nil
}

func (d *containerdDriver) Wait(ctx context.Context, project, id string) (Exit, error) {
	ctx = scope(ctx, project)
	task, err := d.task(ctx, id)
	if err != nil {
		return Exit{}, err
	}
	exited, err := task.Wait(ctx)
	if err != nil {
		return Exit{}, fmt.Errorf("wait %s: %w", id, err)
	}
	select {
	case status := <-exited:
		return Exit{
			ID: id, ExitCode: status.ExitCode(), ExitedAt: status.ExitTime(), Err: status.Error(),
		}, nil
	case <-ctx.Done():
		return Exit{}, ctx.Err()
	}
}

// Exits streams task exits. This is the reconciler's crash signal: subscribing
// beats polling, because a container that dies and is restarted between polls
// would otherwise be invisible (M0 spike ②).
func (d *containerdDriver) Exits(ctx context.Context, project string) (<-chan Exit, error) {
	ctx = scope(ctx, project)
	envelopes, errs := d.client.Subscribe(ctx, `topic=="/tasks/exit"`)

	out := make(chan Exit)
	go func() {
		defer close(out)
		for {
			select {
			case env, ok := <-envelopes:
				if !ok {
					return
				}
				exit, err := decodeExit(env)
				if err != nil {
					d.log.Warn("cannot decode task exit event", "error", err)
					continue
				}
				select {
				case out <- exit:
				case <-ctx.Done():
					return
				}
			case err, ok := <-errs:
				if !ok {
					return
				}
				if err != nil && !errors.Is(err, context.Canceled) {
					select {
					case out <- Exit{Err: fmt.Errorf("event stream: %w", err)}:
					case <-ctx.Done():
					}
				}
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// Exec runs a command inside a running alloc and returns its exit code.
//
// This is what backs the `exec` health check (PRD §6.2 R7). The command is an
// argument array and is executed directly — never through a shell, which would
// make a health check a command-injection vector (§14, A03).
//
// The exec process inherits the task's namespaces and cgroup, so a health check
// counts against the alloc's own limits rather than escaping them. Its output
// is discarded: a check reports pass or fail, and streaming an arbitrary
// command's output into the control plane's logs is a way to fill a disk.
func (d *containerdDriver) Exec(ctx context.Context, project, id string, cmd []string, timeout time.Duration) (uint32, error) {
	if len(cmd) == 0 {
		return 0, fmt.Errorf("%w: empty exec command", ErrInvalidSpec)
	}
	ctx = scope(ctx, project)

	task, err := d.execTask(ctx, id)
	if err != nil {
		return 0, err
	}
	spec, err := task.Spec(ctx)
	if err != nil {
		return 0, fmt.Errorf("spec of %s: %w", id, err)
	}

	// Start from the task's own process spec so the exec keeps its user,
	// environment and working directory, then replace only the command.
	process := *spec.Process
	process.Args = cmd
	process.Terminal = false

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The exec id must be unique per in-flight exec on the task; the alloc's
	// probe is serialised by the caller, so the deadline is enough to make it so.
	execID := "kanea-health-" + strconv.FormatInt(deadlineNonce(ctx), 10)

	proc, err := task.Exec(ctx, execID, &process, cio.NullIO)
	if err != nil {
		return 0, fmt.Errorf("exec in %s: %w", id, err)
	}
	defer func() {
		// Always reap: a leaked exec process holds its parent task's resources
		// and shows up in the alloc's pids limit.
		if _, delErr := proc.Delete(context.WithoutCancel(ctx), containerd.WithProcessKill); delErr != nil {
			d.log.Debug("cleaning up health exec", "alloc", id, "error", delErr)
		}
	}()

	statusC, err := proc.Wait(ctx)
	if err != nil {
		return 0, fmt.Errorf("wait exec in %s: %w", id, err)
	}
	if err := proc.Start(ctx); err != nil {
		return 0, fmt.Errorf("start exec in %s: %w", id, err)
	}

	select {
	case <-ctx.Done():
		// A check that never returns is a failed check, not a stalled loop.
		return 0, fmt.Errorf("exec in %s: %w", id, ctx.Err())
	case status := <-statusC:
		code, _, err := status.Result()
		if err != nil {
			return 0, fmt.Errorf("exec in %s: %w", id, err)
		}
		return code, nil
	}
}

// deadlineNonce derives a per-exec id from the context deadline. It only has to
// be distinct among concurrently running execs on one task.
func deadlineNonce(ctx context.Context) int64 {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline.UnixNano()
	}
	return 0
}

func (d *containerdDriver) task(ctx context.Context, id string) (containerd.Task, error) {
	container, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("load %s: %w", id, err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("%w: task of %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("task of %s: %w", id, err)
	}
	return task, nil
}

// execTask is task() plus the exec refusal for runtimes that have none.
//
// The wasmtime shim implements no exec — a wasm sandbox holds exactly one
// instance — so an exec against a function alloc must fail as ErrNoExec, with
// the reason, rather than as whatever gRPC error the shim's stub produces.
// jobspec already refuses `exec` health checks on functions (R25); this is the
// runtime-level half of that refusal, for `kanea exec` and for anything that
// reached the driver another way.
func (d *containerdDriver) execTask(ctx context.Context, id string) (containerd.Task, error) {
	container, err := d.client.LoadContainer(ctx, id)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("load %s: %w", id, err)
	}
	if info, err := container.Info(ctx); err == nil && info.Runtime.Name == RuntimeWasmtime {
		return nil, fmt.Errorf("%w: %s is a wasm function (PRD §6.2 R25); use its http endpoint or logs", ErrNoExec, id)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("%w: task of %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("task of %s: %w", id, err)
	}
	return task, nil
}

func snapshotID(allocID string) string { return allocID + "-snap" }

// labels make allocs attributable without consulting the Store — useful when
// reconciling drift and when a human is looking at `ctr containers ls`.
func labels(spec AllocSpec) map[string]string {
	return map[string]string{
		"kanea":         "true",
		"kanea.project": spec.Project,
		"kanea.service": spec.Service,
		"kanea.alloc":   spec.ID,
	}
}

func mapState(s containerd.ProcessStatus) State {
	switch s {
	case containerd.Created:
		return StateCreated
	case containerd.Running:
		return StateRunning
	case containerd.Stopped:
		return StateStopped
	case containerd.Paused, containerd.Pausing:
		return StatePaused
	default:
		return StateUnknown
	}
}

// decodeExit turns a /tasks/exit envelope into an Exit. containerd delivers the
// payload as a typed Any; anything else on this topic is a protocol surprise
// worth reporting rather than dropping silently.
func decodeExit(env *events.Envelope) (Exit, error) {
	if env == nil || env.Event == nil {
		return Exit{}, errors.New("empty event envelope")
	}
	decoded, err := typeurl.UnmarshalAny(env.Event)
	if err != nil {
		return Exit{}, fmt.Errorf("unmarshal event: %w", err)
	}
	exit, ok := decoded.(*apievents.TaskExit)
	if !ok {
		return Exit{}, fmt.Errorf("unexpected event type %T on /tasks/exit", decoded)
	}
	return Exit{
		ID:       exit.ContainerID,
		ExitCode: exit.ExitStatus,
		ExitedAt: exit.ExitedAt.AsTime(),
	}, nil
}

// ExecStream runs a command inside a running alloc with its streams attached.
//
// This is the debug shell of PRD §16.2, and it differs from the health-check
// Exec above in every respect that matters: it carries a person's terminal, it
// has no deadline, and its output goes somewhere. What it shares is the rule
// that matters most — the command is an argument array executed directly, never
// a shell string, so the only shell involved is one the operator named.
//
// The exec process inherits the task's namespaces and cgroup, so a debug shell
// counts against the alloc's own limits rather than escaping them. That is not
// a detail: an exec that ran outside the cgroup would be a way to use memory
// the workload was refused.
func (d *containerdDriver) ExecStream(
	ctx context.Context, project, id string, opts ExecOptions,
) (uint32, error) {
	if len(opts.Command) == 0 {
		return 0, fmt.Errorf("%w: empty exec command", ErrInvalidSpec)
	}
	ctx = scope(ctx, project)

	task, err := d.execTask(ctx, id)
	if err != nil {
		return 0, err
	}
	spec, err := task.Spec(ctx)
	if err != nil {
		return 0, fmt.Errorf("spec of %s: %w", id, err)
	}

	// Start from the task's own process spec so the exec keeps the workload's
	// user, environment and working directory. An operator debugging a service
	// wants the service's world, not a default one.
	process := *spec.Process
	process.Args = opts.Command
	process.Terminal = opts.TTY
	if opts.User != "" {
		// Deliberately narrow: a numeric uid only. Resolving a name would mean
		// reading the container's /etc/passwd from the host, and a
		// container-controlled file deciding which uid the control plane runs a
		// process as is not a thing to build.
		uid, err := strconv.ParseUint(opts.User, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("%w: exec user must be a numeric uid, got %q",
				ErrInvalidSpec, opts.User)
		}
		process.User.UID = uint32(uid)
	}

	streams := cio.NewCreator(execStreamOpts(opts)...)
	execID := "kanea-exec-" + strconv.FormatInt(time.Now().UnixNano(), 10)

	proc, err := task.Exec(ctx, execID, &process, streams)
	if err != nil {
		return 0, fmt.Errorf("exec in %s: %w", id, err)
	}
	defer func() {
		// Always reap. A leaked exec process holds the task's resources and
		// counts against the alloc's pids limit — and a debug shell someone
		// closed the laptop lid on is exactly how that happens.
		if _, delErr := proc.Delete(context.WithoutCancel(ctx), containerd.WithProcessKill); delErr != nil {
			d.log.Debug("cleaning up exec", "alloc", id, "exec", execID, "error", delErr)
		}
	}()

	statusC, err := proc.Wait(ctx)
	if err != nil {
		return 0, fmt.Errorf("wait exec in %s: %w", id, err)
	}
	if err := proc.Start(ctx); err != nil {
		return 0, fmt.Errorf("start exec in %s: %w", id, err)
	}

	// Resizes are pumped on their own goroutine and stop when the exec does.
	// A terminal that stays the wrong size after the window changed is a small
	// thing that makes a debug session feel broken.
	if opts.TTY && opts.Resize != nil {
		done := make(chan struct{})
		defer close(done)
		go pumpResize(ctx, proc, opts.Resize, done, d.log)
	}

	select {
	case <-ctx.Done():
		// The caller hung up. The deferred Delete kills the process, so a
		// closed terminal does not leave a shell running in the container.
		return 0, fmt.Errorf("exec in %s: %w", id, ctx.Err())
	case status := <-statusC:
		code, _, err := status.Result()
		if err != nil {
			return 0, fmt.Errorf("exec in %s: %w", id, err)
		}
		return code, nil
	}
}

// execStreamOpts builds the cio options for an attached exec.
func execStreamOpts(opts ExecOptions) []cio.Opt {
	stdin, stdout, stderr := opts.Stdin, opts.Stdout, opts.Stderr
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	out := []cio.Opt{cio.WithStreams(stdin, stdout, stderr)}
	if opts.TTY {
		out = append(out, cio.WithTerminal)
	}
	return out
}

// pumpResize forwards terminal size changes until the exec ends.
func pumpResize(
	ctx context.Context, proc containerd.Process,
	sizes <-chan TerminalSize, done <-chan struct{}, log *slog.Logger,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case size, ok := <-sizes:
			if !ok {
				return
			}
			if err := proc.Resize(ctx, uint32(size.Width), uint32(size.Height)); err != nil {
				// Not fatal: a terminal at the wrong size is a nuisance, and
				// killing the session over it would be worse.
				log.Debug("cannot resize an exec terminal", "error", err)
			}
		}
	}
}
