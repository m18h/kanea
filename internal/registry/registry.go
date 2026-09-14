// Package registry is the node's internal build registry (PRD §5.2.14).
//
// A minimal OCI distribution server: exactly the `/v2/` subset a BuildKit
// push and a containerd pull speak, on a loopback listener of its own, backed
// by content-addressed files under the data directory. It exists so that a
// single node can build, push and pull its own images with no external
// registry (§10.2's omitted-target default), and for nothing else: everything
// the two clients do not emit answers UNSUPPORTED rather than accreting.
//
// The `/v2/` prefix is the OCI distribution base path both clients hardcode,
// not a Kanea API version; this server is deliberately not a route on the API
// server, whose auth/CSRF middleware is wrong for this protocol in both
// directions.
//
// Security shape (§14 A08's one stated carve-out): the listener refuses any
// non-loopback bind, reads are anonymous (containerd's pull path is already
// plain-HTTP-for-localhost when unauthenticated), and writes require a
// per-boot credential delivered to BuildKit inside the build's materialised
// config.json - builds run host-networked (§10.2), so a repo-controlled RUN
// step can reach this listener, and with writes gated it can read images, not
// poison them. Repository names accepted on push are bounded to declared
// pipelines, with refusals counted (the attacker-chosen-keys rule).
package registry

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// DefaultAddr is where the registry listens. Not :5000, where a
// user-installed registry conventionally lives; colliding with one would make
// installing Kanea an act that breaks other software (§5.2.4's rule).
const DefaultAddr = "127.0.0.1:5100"

// pushUser is the Basic username the per-boot credential rides under. The
// secret is the password; the username exists because the docker config.json
// format wants one.
const pushUser = "kanea"

// Server limits. The §21 footprint term is bounded by these: writes stream
// through digest verification to disk and reads are served from files, so no
// blob is ever held in memory.
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 2 * time.Minute
	maxHeaderBytes    = 16 << 10
)

// Config configures the registry.
type Config struct {
	// Addr is the loopback host:port to bind. Empty means DefaultAddr; a
	// non-loopback address is refused at New.
	Addr string
	// Dir is the storage root, conventionally <data-dir>/registry. Created
	// 0700 here: blobs are image content, and nothing but kanead reads them
	// from disk.
	Dir string
	// Allowed reports whether a repository may be pushed to. The bound is the
	// control (§5.2.14): a pushed repository must be a declared
	// <project>/<service> pipeline. Nil refuses every write, because a
	// registry that cannot ask is a registry that must not answer.
	Allowed func(ctx context.Context, project, service string) bool
	Logger  *slog.Logger
	Now     func() time.Time
}

// Registry is the internal build registry.
type Registry struct {
	listener net.Listener
	password string
	store    *contentStore
	allowed  func(ctx context.Context, project, service string) bool
	log      *slog.Logger
	now      func() time.Time

	refusals refusals
}

// New validates the configuration, binds the listener and mints the per-boot
// push credential.
//
// The bind happens here rather than in Serve because the pipeline needs the
// concrete address before the serve goroutine starts: a configured port of 0
// resolves to an ephemeral one, and the defaulted build target must name the
// port that answers.
func New(cfg Config) (*Registry, error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	if cfg.Dir == "" {
		return nil, errors.New("registry: a storage directory is required")
	}
	if err := validateLoopback(cfg.Addr); err != nil {
		return nil, err
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	store, err := newContentStore(cfg.Dir, cfg.Now)
	if err != nil {
		return nil, err
	}
	// The boot half of retention: the write-triggered sweep never ran for
	// whatever the last process wrote on its way down.
	store.sweep(cfg.Logger)

	// The per-boot write credential: minted here, held in memory, never
	// persisted or logged. It leaves this process exactly once per build,
	// inside the materialised config.json (PushDockerConfig).
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("registry: mint push credential: %w", err)
	}

	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("registry: listen %s: %w", cfg.Addr, err)
	}

	return &Registry{
		listener: listener,
		password: hex.EncodeToString(secret),
		store:    store,
		allowed:  cfg.Allowed,
		log:      cfg.Logger,
		now:      cfg.Now,
	}, nil
}

// validateLoopback refuses anything but a loopback bind.
//
// Stricter than the internal DNS's node-local rule (K-27), deliberately: the
// registry's reads are anonymous by design, so on any routable address it is
// an image server for whoever can reach it. A control that cannot be enforced
// is refused, and there is no warn-loudly tier here.
func validateLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("registry: listen address %q: %w", listen, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("registry: listen address %q must be an IP, not a name: %w", listen, err)
	}
	if !addr.IsLoopback() {
		return fmt.Errorf("registry: refusing to listen on %s; the internal registry serves "+
			"anonymous reads and binds loopback only (§5.2.14)", host)
	}
	return nil
}

// Addr is the bound address, stable from New onward.
func (r *Registry) Addr() string {
	return r.listener.Addr().String()
}

// PushDockerConfig renders the per-boot credential as a docker config.json
// granting push access to this registry and nothing else.
//
// It rides the build's existing materialised-credential path (§10.2): a Basic
// entry containerd's authorizer inside buildkitd answers the challenge with,
// so no token service exists.
func (r *Registry) PushDockerConfig() []byte {
	auth := base64.StdEncoding.EncodeToString([]byte(pushUser + ":" + r.password))
	body, err := json.Marshal(map[string]any{
		"auths": map[string]any{r.Addr(): map[string]string{"auth": auth}},
	})
	if err != nil {
		// A marshal of maps of strings cannot fail; if it somehow does, an
		// empty config makes the push fail authentication, which is closed.
		return nil
	}
	return body
}

// Serve answers requests until ctx is cancelled.
func (r *Registry) Serve(ctx context.Context) error {
	server := &http.Server{
		Handler:           r.handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	go func() {
		<-ctx.Done()
		// Close, not Shutdown: an upload in flight belongs to a build that is
		// dying with the daemon anyway, and its session file is wiped at the
		// next boot.
		if err := server.Close(); err != nil {
			r.log.Debug("closing registry listener", "error", err)
		}
	}()

	r.log.Info("internal registry listening", "address", r.Addr())
	err := server.Serve(r.listener)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return fmt.Errorf("registry: serve: %w", err)
}
