package provision

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// fakeLayers serves synthesised layer blobs, so the layer-walking logic is
// testable without a containerd or a 600 MiB image.
type fakeLayers struct {
	blobs map[digest.Digest][]byte
	// read records which layers were opened, so the early exit can be checked.
	read []digest.Digest
}

func (f *fakeLayers) Open(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	body, ok := f.blobs[desc.Digest]
	if !ok {
		return nil, errors.New("no such blob")
	}
	f.read = append(f.read, desc.Digest)
	return io.NopCloser(bytes.NewReader(body)), nil
}

// layer builds one gzipped tar layer and its descriptor.
func layer(t *testing.T, f *fakeLayers, members map[string]string) ocispec.Descriptor {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, body := range members {
		typeflag := byte(tar.TypeReg)
		size := int64(len(body))
		if body == "" {
			// An empty body is how these tests spell a whiteout marker.
			size = 0
		}
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Typeflag: typeflag, Mode: 0o755, Size: size,
		}); err != nil {
			t.Fatal(err)
		}
		if size > 0 {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	body := buf.Bytes()
	d := digest.FromBytes(body)
	if f.blobs == nil {
		f.blobs = map[digest.Digest][]byte{}
	}
	f.blobs[d] = body
	return ocispec.Descriptor{Digest: d, Size: int64(len(body))}
}

func TestExtractFromLayersTakesTheTopmostCopy(t *testing.T) {
	f := &fakeLayers{}
	base := layer(t, f, map[string]string{"usr/bin/buildctl": "old"})
	top := layer(t, f, map[string]string{"usr/bin/buildctl": "new"})

	dest := t.TempDir()
	err := extractFromLayers(context.Background(), f,
		[]ocispec.Descriptor{base, top},
		[]File{{From: "usr/bin/buildctl", To: "bin/buildctl", Mode: "0755"}},
		dest)
	if err != nil {
		t.Fatalf("extractFromLayers: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "bin/buildctl"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Errorf("took %q, want the topmost layer's copy", got)
	}
}

// The early exit is what makes reading a 600 MiB image affordable: once every
// wanted file is found, the layers below it are never opened.
func TestExtractFromLayersStopsOnceEverythingIsFound(t *testing.T) {
	f := &fakeLayers{}
	deep := layer(t, f, map[string]string{"usr/bin/other": "x"})
	top := layer(t, f, map[string]string{"usr/bin/buildctl": "found"})

	dest := t.TempDir()
	err := extractFromLayers(context.Background(), f,
		[]ocispec.Descriptor{deep, top},
		[]File{{From: "usr/bin/buildctl", To: "bin/buildctl", Mode: "0755"}},
		dest)
	if err != nil {
		t.Fatalf("extractFromLayers: %v", err)
	}
	if len(f.read) != 1 || f.read[0] != top.Digest {
		t.Errorf("read %d layers, want only the topmost", len(f.read))
	}
}

// A file deleted by a later layer is not in the image, and installing the copy
// from an earlier one would put something on the host the image does not have.
func TestExtractFromLayersHonoursWhiteouts(t *testing.T) {
	f := &fakeLayers{}
	base := layer(t, f, map[string]string{"usr/bin/buildctl": "removed later"})
	top := layer(t, f, map[string]string{"usr/bin/.wh.buildctl": ""})

	dest := t.TempDir()
	err := extractFromLayers(context.Background(), f,
		[]ocispec.Descriptor{base, top},
		[]File{{From: "usr/bin/buildctl", To: "bin/buildctl", Mode: "0755"}},
		dest)
	if err == nil {
		t.Fatal("a whited-out file was extracted from a lower layer")
	}
	if _, err := os.Stat(filepath.Join(dest, "bin/buildctl")); err == nil {
		t.Error("the deleted file was written to the host")
	}
}

// Upstream images move binaries between releases; failing an install over a
// path that shifted would be a worse trade than looking in both.
func TestExtractFromLayersUsesTheAltPath(t *testing.T) {
	f := &fakeLayers{}
	only := layer(t, f, map[string]string{"usr/local/bin/buildctl": "binary"})

	dest := t.TempDir()
	err := extractFromLayers(context.Background(), f,
		[]ocispec.Descriptor{only},
		[]File{{From: "usr/bin/buildctl", Alt: "usr/local/bin/buildctl", To: "bin/buildctl", Mode: "0755"}},
		dest)
	if err != nil {
		t.Fatalf("extractFromLayers: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "bin/buildctl")); string(got) != "binary" {
		t.Errorf("alt path was not used, got %q", got)
	}
}

// A layer naming a path outside the rootfs is not a layer to take a binary
// from, whatever else it contains.
func TestExtractFromLayersRefusesEscapingMembers(t *testing.T) {
	f := &fakeLayers{}
	evil := layer(t, f, map[string]string{"../../etc/cron.d/x": "payload"})

	dest := t.TempDir()
	err := extractFromLayers(context.Background(), f,
		[]ocispec.Descriptor{evil},
		[]File{{From: "usr/bin/buildctl", To: "bin/buildctl", Mode: "0755"}},
		dest)
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("error was %v, want ErrUnsafePath", err)
	}
}

func TestExtractFromLayersReportsAMissingBinary(t *testing.T) {
	f := &fakeLayers{}
	only := layer(t, f, map[string]string{"usr/bin/something-else": "x"})

	err := extractFromLayers(context.Background(), f,
		[]ocispec.Descriptor{only},
		[]File{{From: "usr/bin/buildkitd", To: "bin/buildkitd", Mode: "0755"}},
		t.TempDir())
	if err == nil {
		t.Fatal("a missing binary was not reported")
	}
	for _, want := range []string{"buildkitd", "not in the image"} {
		if !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}
