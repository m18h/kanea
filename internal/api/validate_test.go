package api_test

import (
	"context"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/storage"
)

// The apply seam's validateDesired: the parser enforces the spec's invariants
// one way, and PUT /v1/services is another way a record reaches the Store.
// Each test writes the record a parser could never produce and requires the
// refusal here - the R22 port-policy shape, for the rest of the list.

func TestApplyRefusesTraversalNames(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A name jobspec would refuse at parse, arriving as JSON: the components
	// compose into host paths the reconciler builds as root (volume
	// directories, resolv.conf, log files).
	bad := testService("web", 1)
	bad.Project = "../../../../etc/cron.d"
	if _, err := h.client.Apply(ctx, []reconciler.Desired{bad}, nil); err == nil ||
		!strings.Contains(err.Error(), "DNS-1123") {
		t.Fatalf("a traversal project name applied: %v", err)
	}

	badService := testService("../x", 1)
	if _, err := h.client.Apply(ctx, []reconciler.Desired{badService}, nil); err == nil {
		t.Fatal("a traversal service name applied")
	}

	badVolume := testService("web", 1)
	badVolume.Volumes = []reconciler.Volume{{Name: "../../etc", MountPath: "/data"}}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{badVolume}, nil); err == nil ||
		!strings.Contains(err.Error(), "DNS-1123") {
		t.Fatalf("a traversal volume name applied: %v", err)
	}

	// And nothing landed in the Store from any of them.
	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	if len(services) != 0 {
		t.Fatalf("services = %d; a refused record was stored", len(services))
	}
}

func TestApplyRefusesWhatTheCapabilityAllowlistRefuses(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	bad := testService("web", 1)
	bad.Capabilities = []string{"CAP_SYS_ADMIN"}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{bad}, nil); err == nil ||
		!strings.Contains(err.Error(), "CAP_SYS_ADMIN") {
		t.Fatalf("CAP_SYS_ADMIN applied: %v", err)
	}

	// The permitted set still applies cleanly, as does the none token.
	good := testService("web", 1)
	good.Capabilities = []string{"CAP_NET_RAW", "CAP_CHOWN"}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{good}, nil); err != nil {
		t.Fatalf("a permitted list refused: %v", err)
	}
}

func TestApplyRefusesCrossProjectCredentialReferences(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// An inline storage resource: validateVolumes never ran, so the R5 check
	// lives here (v1.72's rule, apply half).
	bad := testService("web", 1)
	bad.Volumes = []reconciler.Volume{{
		Name: "data", MountPath: "/data",
		Resource: storage.Resource{
			Name: "assets", Type: "s3", Bucket: "media",
			AuthRef: "secret:bank/aws-creds",
		},
	}}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{bad}, nil); err == nil ||
		!strings.Contains(err.Error(), "another project") {
		t.Fatalf("a cross-project storage credential applied: %v", err)
	}

	// The cleartext endpoint the credential would be sent to.
	badEndpoint := testService("web", 1)
	badEndpoint.Volumes = []reconciler.Volume{{
		Name: "data", MountPath: "/data",
		Resource: storage.Resource{
			Name: "assets", Type: "s3", Bucket: "media",
			Endpoint: "http://minio.lan:9000", AuthRef: "secret:shop/s3",
		},
	}}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{badEndpoint}, nil); err == nil ||
		!strings.Contains(err.Error(), "https") {
		t.Fatalf("a cleartext endpoint applied: %v", err)
	}

	// An env reference into another project.
	badEnv := testService("web", 1)
	badEnv.Env = map[string]string{"DATABASE_URL": "secret:bank/database-url"}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{badEnv}, nil); err == nil ||
		!strings.Contains(err.Error(), "another project") {
		t.Fatalf("a cross-project env reference applied: %v", err)
	}

	// Same-project and shared/ references are the R5 vocabulary: they apply.
	good := testService("web", 1)
	good.Volumes = []reconciler.Volume{{
		Name: "data", MountPath: "/data",
		Resource: storage.Resource{
			Name: "assets", Type: "s3", Bucket: "media",
			Endpoint: "https://minio.lan:9443", AuthRef: "secret:shared/s3",
		},
	}}
	good.Env = map[string]string{"DATABASE_URL": "secret:shop/database-url"}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{good}, nil); err != nil {
		t.Fatalf("an R5-clean record refused: %v", err)
	}
}

func TestApplyRefusesTheFullR25List(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	wasm := func() reconciler.Desired {
		d := testService("fn", 1)
		d.Runtime = runtime.RuntimeWasmtime
		return d
	}

	for _, tc := range []struct {
		name   string
		mutate func(*reconciler.Desired)
	}{
		{"volumes", func(d *reconciler.Desired) {
			d.Volumes = []reconciler.Volume{{Name: "data", MountPath: "/data"}}
		}},
		{"devices", func(d *reconciler.Desired) {
			d.Devices = []reconciler.DeviceRequest{{Name: "gpu"}}
		}},
		{"sockets", func(d *reconciler.Desired) {
			d.Sockets = []reconciler.SocketRequest{{Name: "docker", MountPath: "/run/docker.sock"}}
		}},
		{"capabilities", func(d *reconciler.Desired) {
			d.Capabilities = []string{"CAP_CHOWN"}
		}},
		{"user", func(d *reconciler.Desired) {
			d.User = &runtime.User{UID: 1000}
		}},
		{"scaling", func(d *reconciler.Desired) {
			d.Scaling = &reconciler.ScalingPolicy{Max: 4}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := wasm()
			tc.mutate(&d)
			if _, err := h.client.Apply(ctx, []reconciler.Desired{d}, nil); err == nil ||
				!strings.Contains(err.Error(), "R25") {
				t.Fatalf("a wasm service with %s applied: %v", tc.name, err)
			}
		})
	}
}

func TestApplyRefusesDisagreeingRouteAuth(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The verifier bundle is one entry per service (v1.40), and the
	// projection stands the first route's auth for all of them: a second
	// block with different auth would serve unauthenticated.
	d := testService("web", 1)
	d.Expose = &reconciler.Expose{
		Domains: []string{"a.example.com"}, Port: 8080,
		Auth: &reconciler.AuthPolicy{BearerRef: "secret:shop/tokens"},
	}
	d.ExtraExposes = []reconciler.Expose{{
		Domains: []string{"b.example.com"}, Port: 8080,
		Auth: &reconciler.AuthPolicy{BasicRef: "secret:shop/htpasswd"},
	}}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{d}, nil); err == nil ||
		!strings.Contains(err.Error(), "R16") {
		t.Fatalf("disagreeing route auth applied: %v", err)
	}

	// Identical auth across blocks is the v1.50 contract: it applies.
	d.ExtraExposes[0].Auth = &reconciler.AuthPolicy{BearerRef: "secret:shop/tokens"}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{d}, nil); err != nil {
		t.Fatalf("identical route auth refused: %v", err)
	}
}

func TestApplyRefusesABadPipelineProject(t *testing.T) {
	h := newHarness(t)

	_, err := h.client.Apply(context.Background(),
		[]reconciler.Desired{testService("web", 1)},
		[]gitops.Config{{Project: "../../etc"}})
	if err == nil || !strings.Contains(err.Error(), "DNS-1123") {
		t.Fatalf("a traversal pipeline project applied: %v", err)
	}
}

// TestTheFeedElidesFileContentAndTheListDoesNot (PRD v1.85, R35).
//
// Two opposite requirements that must not be conflated. The websocket feed
// ships every service's whole record to every subscriber on every store-index
// change, so bulk bytes there are the v1.70 send-buffer defect in a new place.
// But GET /v1/services must keep the content: there is no per-service GET, so
// `kanea deploy` round-trips the whole record through the list, and eliding it
// there would make every deploy silently delete every config file on the node.
func TestTheFeedElidesFileContentAndTheListDoesNot(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	d := testService("web", 1)
	d.Files = []reconciler.FileMount{{
		Name: "conf", Path: "/etc/app.conf", Content: []byte("listen=8080"),
	}}
	if _, err := h.client.Apply(ctx, []reconciler.Desired{d}, nil); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// The REST list keeps the bytes: a deploy reads through it.
	services, err := h.client.Services(ctx)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	var listed *reconciler.Desired
	for i := range services {
		if services[i].Service == "web" {
			listed = &services[i]
		}
	}
	if listed == nil || len(listed.Files) != 1 {
		t.Fatalf("the service or its file is missing from the list: %+v", listed)
	}
	if string(listed.Files[0].Content) != "listen=8080" {
		t.Errorf("GET /v1/services elided file content (%q); `kanea deploy` round-trips "+
			"through this list, so every deploy would delete every config file",
			listed.Files[0].Content)
	}
}
