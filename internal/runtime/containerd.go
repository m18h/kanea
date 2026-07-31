package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

// DefaultSocket is containerd's usual gRPC socket.
const DefaultSocket = "/run/containerd/containerd.sock"

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

func (d *containerdDriver) EnsureImage(ctx context.Context, project, ref string) (string, error) {
	ctx = scope(ctx, project)

	if img, err := d.client.GetImage(ctx, ref); err == nil {
		return img.Target().Digest.String(), nil
	} else if !errdefs.IsNotFound(err) {
		return "", fmt.Errorf("look up image %s: %w", ref, err)
	}

	d.log.Info("pulling image", "project", project, "ref", ref)
	img, err := d.client.Pull(ctx, ref, containerd.WithPullUnpack)
	if err != nil {
		return "", fmt.Errorf("pull %s: %w", ref, err)
	}
	return img.Target().Digest.String(), nil
}

func (d *containerdDriver) Create(ctx context.Context, spec AllocSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	ctx = scope(ctx, spec.Project)

	img, err := d.client.GetImage(ctx, spec.Image)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return fmt.Errorf("image %s not pulled: %w", spec.Image, err)
		}
		return fmt.Errorf("look up image %s: %w", spec.Image, err)
	}

	// Image config first, then our options: hardening and limits must win over
	// anything the image asks for.
	opts := append([]oci.SpecOpts{oci.WithImageConfig(img)}, specOpts(spec)...)

	container, err := d.client.NewContainer(ctx, spec.ID,
		containerd.WithImage(img),
		containerd.WithNewSnapshot(snapshotID(spec.ID), img),
		containerd.WithNewSpec(opts...),
		containerd.WithContainerLabels(labels(spec)),
	)
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
