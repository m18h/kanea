package reconciler

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// splitHostPort pulls the address out of an httptest server URL.
func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	trimmed := strings.TrimPrefix(rawURL, "http://")
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port %q: %v", port, err)
	}
	return host, n
}

func TestProbeHTTP(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{name: "200 is healthy", status: http.StatusOK},
		{name: "204 is healthy", status: http.StatusNoContent},
		// A redirect is the service pointing elsewhere, not a statement that it
		// is serving, and following one can probe something entirely different.
		{name: "302 is not healthy", status: http.StatusFound, wantErr: true},
		{name: "404 is not healthy", status: http.StatusNotFound, wantErr: true},
		{name: "500 is not healthy", status: http.StatusInternalServerError, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "http://example.com/")
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			host, port := hostPort(t, srv.URL)
			err := newProber(nil).Probe(t.Context(),
				ProbeTarget{AllocID: "shop-web-0", IPv4: host},
				HealthCheck{Type: HealthHTTP, Path: "/healthz", Port: port})

			if tc.wantErr && err == nil {
				t.Fatal("Probe = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Probe = %v, want nil", err)
			}
		})
	}
}

// A check that hangs must fail on its own timeout rather than stalling the
// reconcile pass it runs inside.
func TestProbeHTTPHonoursTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	host, port := hostPort(t, srv.URL)
	start := time.Now()
	err := newProber(nil).Probe(t.Context(),
		ProbeTarget{AllocID: "shop-web-0", IPv4: host},
		HealthCheck{Type: HealthHTTP, Port: port, Timeout: 200 * time.Millisecond})

	if err == nil {
		t.Fatal("Probe = nil, want a timeout")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v; the timeout is not bounding the probe", elapsed)
	}
}

func TestProbeTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port := hostPort(t, "http://"+ln.Addr().String())

	p := newProber(nil)
	check := HealthCheck{Type: HealthTCP, Port: port}
	target := ProbeTarget{AllocID: "shop-web-0", IPv4: host}

	if err := p.Probe(t.Context(), target, check); err != nil {
		t.Fatalf("Probe on an open port = %v, want nil", err)
	}

	// A closed port is the whole signal a tcp check carries.
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := p.Probe(t.Context(), target, check); err == nil {
		t.Fatal("Probe on a closed port = nil, want an error")
	}
}

// fakeExecer stands in for the containerd driver.
type fakeExecer struct {
	code uint32
	err  error
	cmd  []string
}

func (f *fakeExecer) Exec(_ context.Context, _, _ string, cmd []string, _ time.Duration) (uint32, error) {
	f.cmd = cmd
	return f.code, f.err
}

func TestProbeExec(t *testing.T) {
	tests := []struct {
		name    string
		exec    *fakeExecer
		wantErr bool
	}{
		{name: "exit 0 is healthy", exec: &fakeExecer{}},
		{name: "non-zero exit is not healthy", exec: &fakeExecer{code: 1}, wantErr: true},
		{name: "exec failure is not healthy", exec: &fakeExecer{err: errors.New("no task")}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := newProber(tc.exec).Probe(t.Context(),
				ProbeTarget{Project: "shop", AllocID: "shop-web-0"},
				HealthCheck{Type: HealthExec, Command: []string{"pg_isready", "-q"}})

			if tc.wantErr != (err != nil) {
				t.Fatalf("Probe = %v, wantErr = %v", err, tc.wantErr)
			}
			// The command must reach the driver as an array. A shell string here
			// would make a health check an injection vector (§14, A03).
			if len(tc.exec.cmd) != 2 || tc.exec.cmd[0] != "pg_isready" {
				t.Errorf("driver received %v, want the argument array intact", tc.exec.cmd)
			}
		})
	}
}

// A driver that cannot exec must say so rather than let the check pass: a
// silently-passing health check is worse than none.
func TestProbeExecWithoutADriver(t *testing.T) {
	err := newProber(nil).Probe(t.Context(),
		ProbeTarget{AllocID: "shop-web-0"},
		HealthCheck{Type: HealthExec, Command: []string{"true"}})

	if err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("Probe = %v, want a refusal", err)
	}
}

func TestProbeUnknownType(t *testing.T) {
	err := newProber(nil).Probe(t.Context(),
		ProbeTarget{AllocID: "shop-web-0"}, HealthCheck{Type: "ping"})
	if err == nil {
		t.Fatal("Probe = nil, want an error for an unknown check type")
	}
}

// The `failures` threshold is what stops a transient blip from taking a
// dependency (and everything downstream of it) out of service.
func TestApplyProbeThreshold(t *testing.T) {
	now := time.Now()
	check := HealthCheck{Type: HealthTCP, Failures: 3, Interval: time.Second}
	record := AllocRecord{ID: "shop-web-0", Healthy: true}

	fail := errors.New("connection refused")

	// Two failures below the threshold leave the alloc healthy.
	for i := 1; i <= 2; i++ {
		record, _ = applyProbe(record, check, fail, now)
		if !record.Healthy {
			t.Fatalf("marked unhealthy after %d failures, threshold is 3", i)
		}
		if record.HealthFailures != i {
			t.Fatalf("failures = %d, want %d", record.HealthFailures, i)
		}
	}

	// The third crosses it.
	record, _ = applyProbe(record, check, fail, now)
	if record.Healthy {
		t.Fatal("still healthy after reaching the failure threshold")
	}
	if record.HealthMessage == "" {
		t.Error("no message explaining the failure")
	}

	// One pass clears everything.
	record, _ = applyProbe(record, check, nil, now)
	if !record.Healthy || record.HealthFailures != 0 || record.HealthMessage != "" {
		t.Fatalf("a passing probe did not reset the record: %+v", record)
	}
}

func TestApplyProbeReportsChangeOnlyWhenItMatters(t *testing.T) {
	now := time.Now()
	check := HealthCheck{Type: HealthTCP, Interval: time.Minute}
	record := AllocRecord{ID: "shop-web-0", Healthy: true, LastProbeAt: now}

	// A pass on an already-healthy alloc within the interval changes nothing a
	// reader cares about, so it must not cost a Store write every pass.
	if _, changed := applyProbe(record, check, nil, now); changed {
		t.Error("an unchanged healthy probe reported a change")
	}
	// A failure always matters.
	if _, changed := applyProbe(record, check, errors.New("nope"), now); !changed {
		t.Error("a failure did not report a change")
	}
}

func TestHealthCheckDefaults(t *testing.T) {
	var absent *HealthCheck
	if absent.configured() {
		t.Error("a nil check reports as configured")
	}
	if absent.interval() != DefaultCheckInterval {
		t.Errorf("interval = %v", absent.interval())
	}
	if absent.timeout() != DefaultCheckTimeout {
		t.Errorf("timeout = %v", absent.timeout())
	}
	if absent.failureThreshold() != DefaultCheckFailures {
		t.Errorf("failures = %d", absent.failureThreshold())
	}

	empty := &HealthCheck{Type: HealthTCP}
	if !empty.configured() {
		t.Error("a declared check reports as unconfigured")
	}
}
