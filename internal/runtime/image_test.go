package runtime_test

import (
	"testing"

	"github.com/kanea-dev/kanea/internal/runtime"
)

// R8 promises that the minimal service is just an image, and every PRD example
// writes the short form. containerd's client does not expand it: the reference
// reaches the resolver as a URL and fails with "invalid port after host".
func TestNormalizeRef(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"bare name", "nginx", "docker.io/library/nginx:latest"},
		{"name and tag", "nginx:1.27-alpine", "docker.io/library/nginx:1.27-alpine"},
		{"official with owner", "kanea/agent:v1", "docker.io/kanea/agent:v1"},
		{"already qualified", "registry.example.com/shop/api:0.9.1", "registry.example.com/shop/api:0.9.1"},
		{"qualified with port", "registry.example.com:5000/shop/api:0.9.1", "registry.example.com:5000/shop/api:0.9.1"},
		{
			"digest pinned",
			"nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			"docker.io/library/nginx@sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		{"docker.io explicit", "docker.io/library/busybox:1.37", "docker.io/library/busybox:1.37"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := runtime.NormalizeRef(tc.in)
			if err != nil {
				t.Fatalf("NormalizeRef(%q) = %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeRef(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeRefRejectsNonsense(t *testing.T) {
	for _, in := range []string{"", "NGINX:latest", "nginx::", "nginx:bad tag", "/leading-slash"} {
		if got, err := runtime.NormalizeRef(in); err == nil {
			t.Errorf("NormalizeRef(%q) = %q, want an error", in, got)
		}
	}
}
