package reconciler

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/passthrough"
)

// fakeGrants stands in for the node's passthrough config. The real policy is
// tested in internal/passthrough; what matters here is what the reconciler does
// with an answer, including a refusal.
type fakeGrants struct {
	devices map[string][]passthrough.Device
	sockets map[string]string
	err     error
}

func (f fakeGrants) ResolveDevice(_, grant string) ([]passthrough.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	d, ok := f.devices[grant]
	if !ok {
		return nil, errors.New("no such grant")
	}
	return d, nil
}

func (f fakeGrants) ResolveSocket(_, grant string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	s, ok := f.sockets[grant]
	if !ok {
		return "", errors.New("no such grant")
	}
	return s, nil
}

func passthroughDesired() Desired {
	return Desired{
		Project: "media",
		Service: "jellyfin",
		Count:   1,
		Image:   "jellyfin:10.9",
		Devices: []DeviceRequest{{Name: "dri", Grant: "gpu"}},
		Sockets: []SocketRequest{
			{Name: "rt", Grant: "containerd", MountPath: "/var/run/docker.sock"},
		},
	}
}

func TestResolvedGrantsReachTheAllocSpec(t *testing.T) {
	r := &Reconciler{passthrough: fakeGrants{
		devices: map[string][]passthrough.Device{
			"gpu": {{Path: "/dev/dri/renderD128", Perms: "rw"}},
		},
		sockets: map[string]string{"containerd": "/run/kanea/containerd.sock"},
	}}

	d := passthroughDesired()
	if err := r.ensurePassthrough(d); err != nil {
		t.Fatalf("ensurePassthrough: %v", err)
	}

	spec := AllocSpecFor(d, 0, "", "")

	if len(spec.Devices) != 1 {
		t.Fatalf("spec has %d devices, want 1", len(spec.Devices))
	}
	if spec.Devices[0].Path != "/dev/dri/renderD128" {
		t.Errorf("device path = %q, want the resolved node", spec.Devices[0].Path)
	}
	if spec.Devices[0].Perms != "rw" {
		t.Errorf("device perms = %q, want rw", spec.Devices[0].Perms)
	}

	var found bool
	for _, m := range spec.Mounts {
		if m.Destination != "/var/run/docker.sock" {
			continue
		}
		found = true
		if m.Source != "/run/kanea/containerd.sock" {
			t.Errorf("socket source = %q, want the node's socket", m.Source)
		}
		// A socket bind should never carry setuid, executables or device nodes.
		for _, want := range []string{"nosuid", "noexec", "nodev"} {
			if !slices.Contains(m.Options, want) {
				t.Errorf("socket mount options %v are missing %q", m.Options, want)
			}
		}
	}
	if !found {
		t.Fatalf("no mount at /var/run/docker.sock; mounts = %+v", spec.Mounts)
	}
}

// The default is that the feature does not exist. A spec that asks for a grant
// on a node with no config must fail rather than start without it.
func TestAGrantOnANodeWithNoConfigFailsTheAlloc(t *testing.T) {
	r := &Reconciler{}

	err := r.ensurePassthrough(passthroughDesired())
	if err == nil {
		t.Fatal("a service got its passthrough on a node with no grants configured")
	}
	if !strings.Contains(err.Error(), "--passthrough-config") {
		t.Errorf("error %v does not say how an operator would enable it", err)
	}
}

// A refused grant fails the alloc. There is deliberately no path on which the
// container starts anyway: a transcoder quietly running without its GPU looks
// healthy and does the wrong thing.
func TestARefusedGrantFailsRatherThanStartingWithout(t *testing.T) {
	r := &Reconciler{passthrough: fakeGrants{err: passthrough.ErrNotAllowed}}

	d := passthroughDesired()
	err := r.ensurePassthrough(d)
	if err == nil {
		t.Fatal("a refused grant did not fail the alloc")
	}
	if !errors.Is(err, passthrough.ErrNotAllowed) {
		t.Errorf("error %v does not wrap ErrNotAllowed", err)
	}
	// And nothing partial is left behind for the spec builder to use.
	spec := AllocSpecFor(d, 0, "", "")
	if len(spec.Devices) != 0 {
		t.Errorf("spec carries %d devices after a refusal", len(spec.Devices))
	}
	for _, m := range spec.Mounts {
		if m.Destination == "/var/run/docker.sock" {
			t.Error("spec carries the socket mount after a refusal")
		}
	}
}

// The common case: no grants asked for, so no policy needed. A node without the
// config file must keep running every service that never wanted one.
func TestAServiceWithNoPassthroughNeedsNoPolicy(t *testing.T) {
	r := &Reconciler{}

	if err := r.ensurePassthrough(Desired{Project: "shop", Service: "web"}); err != nil {
		t.Fatalf("a service asking for nothing was refused: %v", err)
	}
}
