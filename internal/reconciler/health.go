package reconciler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// Health check types (PRD §6.2 R7).
const (
	HealthHTTP = "http"
	HealthTCP  = "tcp"
	HealthExec = "exec"
)

// Health check defaults, from the PRD §6.1 example.
const (
	DefaultCheckInterval = 10 * time.Second
	DefaultCheckTimeout  = 2 * time.Second
	DefaultCheckFailures = 3
)

// HealthCheck is a service's liveness probe, resolved from the job spec.
type HealthCheck struct {
	// Type is http, tcp or exec.
	Type string
	// Path is the HTTP path to request.
	Path string
	// Port is the container port to probe, already resolved from its name.
	Port int
	// Command is the argument array for an exec check, never a shell string,
	// which would make a health check a command-injection vector (§14, A03).
	Command []string
	// Interval is how often to probe.
	Interval time.Duration
	// Timeout bounds one probe.
	Timeout time.Duration
	// Failures is how many consecutive failures mark the alloc unhealthy.
	Failures int
}

// configured reports whether a check is actually declared.
func (h *HealthCheck) configured() bool { return h != nil && h.Type != "" }

func (h *HealthCheck) interval() time.Duration {
	if h == nil || h.Interval <= 0 {
		return DefaultCheckInterval
	}
	return h.Interval
}

func (h *HealthCheck) timeout() time.Duration {
	if h == nil || h.Timeout <= 0 {
		return DefaultCheckTimeout
	}
	return h.Timeout
}

func (h *HealthCheck) failureThreshold() int {
	if h == nil || h.Failures <= 0 {
		return DefaultCheckFailures
	}
	return h.Failures
}

// Prober runs one health check against one alloc.
type Prober interface {
	Probe(ctx context.Context, target ProbeTarget, check HealthCheck) error
}

// ProbeTarget is the alloc being probed.
type ProbeTarget struct {
	Project string
	AllocID string
	// IPv4 is the alloc's address, needed by http and tcp checks.
	IPv4 string
}

// Execer runs a command inside an alloc: the runtime capability an exec check
// needs. It is declared here rather than added to Driver so that a Prober can
// be built and tested without a containerd connection.
type Execer interface {
	Exec(ctx context.Context, project, id string, cmd []string, timeout time.Duration) (uint32, error)
}

// netProber is the default Prober.
//
// http and tcp checks dial the alloc's address directly from the host. That
// works because the project isolation policy admits the host entity (the same
// allowance kanea-edge relies on (PRD §7.1)) so a check does not need a policy
// exception of its own.
type netProber struct {
	exec   Execer
	client *http.Client
}

// NewProber builds the default health prober. The Execer backs `exec` checks;
// pass nil when the driver cannot exec, and those checks will report so rather
// than silently pass.
func NewProber(exec Execer) Prober { return newProber(exec) }

func newProber(exec Execer) *netProber {
	return &netProber{
		exec: exec,
		client: &http.Client{
			// Redirects are not followed: a health check asks "is this endpoint
			// serving", and chasing a redirect can turn a check into a probe of
			// something else entirely, including something off-node.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Probe runs the check and returns nil when the alloc is healthy.
func (p *netProber) Probe(ctx context.Context, target ProbeTarget, check HealthCheck) error {
	ctx, cancel := context.WithTimeout(ctx, check.timeout())
	defer cancel()

	switch check.Type {
	case HealthHTTP:
		return p.probeHTTP(ctx, target, check)
	case HealthTCP:
		return p.probeTCP(ctx, target, check)
	case HealthExec:
		return p.probeExec(ctx, target, check)
	default:
		return fmt.Errorf("unknown health check type %q", check.Type)
	}
}

func (p *netProber) probeHTTP(ctx context.Context, target ProbeTarget, check HealthCheck) (err error) {
	if target.IPv4 == "" {
		return fmt.Errorf("alloc %s has no address to probe", target.AllocID)
	}
	path := check.Path
	if path == "" {
		path = "/"
	}
	url := "http://" + net.JoinHostPort(target.IPv4, strconv.Itoa(check.Port)) + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()

	// 2xx only. A 3xx is not "healthy" (it is the service telling us to look
	// somewhere else) and 4xx/5xx are plainly not.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("health check returned %s", resp.Status)
	}
	return nil
}

func (p *netProber) probeTCP(ctx context.Context, target ProbeTarget, check HealthCheck) error {
	if target.IPv4 == "" {
		return fmt.Errorf("alloc %s has no address to probe", target.AllocID)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.IPv4, strconv.Itoa(check.Port)))
	if err != nil {
		return err
	}
	return conn.Close()
}

func (p *netProber) probeExec(ctx context.Context, target ProbeTarget, check HealthCheck) error {
	if p.exec == nil {
		return fmt.Errorf("exec health checks are not available on this driver")
	}
	if len(check.Command) == 0 {
		return fmt.Errorf("exec health check has no command")
	}
	code, err := p.exec.Exec(ctx, target.Project, target.AllocID, check.Command, check.timeout())
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("health check exited with code %d", code)
	}
	return nil
}
