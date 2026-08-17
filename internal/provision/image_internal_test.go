package provision

import "testing"

func TestPinnedDigest(t *testing.T) {
	// The digest is the only thing that authenticates the bytes behind a
	// name; a tag-only reference must be refused here even though the
	// manifest validator refuses it earlier.
	got, err := pinnedDigest("docker.io/moby/buildkit@sha256:40615b4a00f9a791b6fd1d6c41ebfc690e4f4b2e3710240bdd043b4467bc4d7a")
	if err != nil {
		t.Fatalf("pinnedDigest: %v", err)
	}
	if got != "sha256:40615b4a00f9a791b6fd1d6c41ebfc690e4f4b2e3710240bdd043b4467bc4d7a" {
		t.Errorf("pinnedDigest = %q", got)
	}

	for _, ref := range []string{
		"docker.io/moby/buildkit:v0.32.0-rootless",
		"docker.io/moby/buildkit",
		"docker.io/moby/buildkit@sha256:",
	} {
		if _, err := pinnedDigest(ref); err == nil {
			t.Errorf("pinnedDigest(%q) = nil error, want the tag-only refusal", ref)
		}
	}
}
