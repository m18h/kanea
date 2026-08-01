package runtime

import (
	"fmt"

	"github.com/distribution/reference"
)

// NormalizeRef expands an image reference to the fully qualified form
// containerd's client requires.
//
// This is not cosmetic. containerd's client does no normalisation of its own:
// `nginx:1.27-alpine` reaches the resolver as a URL and fails with
//
//	parse "dummy://nginx:1.27-alpine": invalid port ":1.27-alpine" after host
//
// which says nothing about the real problem. The short form is exactly what
// PRD §6.2 R8 promises ("the minimal service is just an image") and what every
// spec example uses, so the driver expands it: `nginx` becomes
// `docker.io/library/nginx:latest`, `nginx:1.27-alpine` becomes
// `docker.io/library/nginx:1.27-alpine`, and an already-qualified reference —
// including a digest-pinned one — is returned unchanged.
//
// Both the pull and the later lookup must use the same expansion, or the pull
// succeeds and the container creation cannot find what it pulled.
func NormalizeRef(ref string) (string, error) {
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return "", fmt.Errorf("image reference %q: %w", ref, err)
	}
	return named.String(), nil
}
