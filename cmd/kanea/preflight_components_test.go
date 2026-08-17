package main

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/m18h/kanea/internal/provision"
)

func scratchLayout(t *testing.T) provision.Layout {
	t.Helper()
	base := t.TempDir()
	return provision.Layout{
		Prefix:  filepath.Join(base, "lib"),
		ConfDir: filepath.Join(base, "etc"),
		DataDir: filepath.Join(base, "data"),
		RunDir:  filepath.Join(base, "run"),
		UnitDir: filepath.Join(base, "units"),
	}
}

// The split is the point: platform checks gate `kanea init` before anything is
// installed, so none of them may be about software the installer places. A
// component check in that set would fail every fresh node on the absence of
// exactly what the next step exists to install.
func TestPlatformChecksDoNotDependOnComponents(t *testing.T) {
	layout := scratchLayout(t)
	results := platformChecks(preflightOptions{
		dataDir: t.TempDir(), layout: layout,
		containerdSocket: filepath.Join(layout.RunDir, "containerd.sock"),
	})

	componentNames := map[string]bool{
		"containerd": true, "buildkit": true, "bpf": true,
		"version matrix": true, "upstream": true, "wasm shim": true,
	}
	for _, r := range results {
		if componentNames[r.Name] {
			t.Errorf("%q is a component check but runs in the platform gate", r.Name)
		}
	}
	if len(results) == 0 {
		t.Fatal("there are no platform checks")
	}
}

// PRD §5.2.11 has said since v1.1 that `kanea doctor` verifies the build
// socket answers, and it never did. §15.4 and §22 R1 say the same about the
// version matrix.
func TestComponentChecksCoverWhatThePRDPromises(t *testing.T) {
	layout := scratchLayout(t)
	results := componentChecks(preflightOptions{
		dataDir: t.TempDir(), layout: layout,
		containerdSocket: filepath.Join(layout.RunDir, "containerd.sock"),
		buildkitSocket:   provision.BuildkitSocket(layout),
		networkMode:      networkEBPF,
		offline:          true,
	})

	got := map[string]bool{}
	for _, r := range results {
		got[r.Name] = true
	}
	for _, want := range []string{
		"containerd",       // §5.2.4
		"bpf",              // §5.2.5: bpffs, cgroup2, and the pin directory
		"buildkit",         // §5.2.11: "that the build socket answers"
		"version matrix",   // §15.4, §22 R1
		"container subnet", // --node-cidr/--cluster-cidr against --service-cidr
		"fuse",             // §8
		"wasm shim",        // §6.2 R25 (v1.39): functions need the wasmtime shim
	} {
		if !got[want] {
			t.Errorf("component checks do not cover %q", want)
		}
	}
}

// --network netns is the development configuration, and it means no datapath
// and therefore nothing for the BPF check to gate on.
func TestNetworkNetnsSkipsTheBPFCheck(t *testing.T) {
	results := componentChecks(preflightOptions{
		dataDir: t.TempDir(), layout: scratchLayout(t),
		networkMode: networkNetns, buildkitSocket: "off", offline: true,
	})
	for _, r := range results {
		if r.Name == "bpf" {
			t.Errorf("--network netns still runs the %q check", r.Name)
		}
	}
}

func TestBuildkitOffSkipsTheBuildCheck(t *testing.T) {
	results := componentChecks(preflightOptions{
		dataDir: t.TempDir(), layout: scratchLayout(t),
		networkMode: networkNetns, buildkitSocket: "off", offline: true,
	})
	for _, r := range results {
		if r.Name == "buildkit" {
			t.Error("--buildkit off still runs the build daemon check")
		}
	}
}

// The one check that touches the network, and the reason --offline exists.
func TestOfflineSkipsTheOnlyNetworkCheck(t *testing.T) {
	opts := preflightOptions{
		dataDir: t.TempDir(), layout: scratchLayout(t),
		networkMode: networkNetns, buildkitSocket: "off", offline: true,
	}
	for _, r := range componentChecks(opts) {
		if r.Name == "upstream" {
			t.Fatal("--offline still probes upstream")
		}
	}
}

// A node where Kanea installed nothing should say so plainly rather than
// listing six failures: the operator has one action to take, not six.
func TestVersionMatrixOnAnEmptyPrefix(t *testing.T) {
	got := checkVersionMatrix(scratchLayout(t))
	if !got.OK || !got.Warn {
		t.Errorf("an uninstalled node reports OK=%v Warn=%v; it should warn, not fail", got.OK, got.Warn)
	}
	if !strings.Contains(got.Fix, "kanea install") {
		t.Errorf("the fix %q does not name the command that resolves it", got.Fix)
	}
}

// A component at a version this build does not pin is a finding: the flag sets
// in §5.2.5 and the file interfaces the spikes found are version-specific.
func TestVersionMatrixDetectsDrift(t *testing.T) {
	layout := scratchLayout(t)
	manifest := provision.MustLoad()
	receipts := filepath.Join(layout.Prefix, ".receipts")
	if err := os.MkdirAll(receipts, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.All() {
		body := `{"name":"` + c.Name + `","version":"0.0.1-wrong","kind":"` + string(c.Kind) + `","arch":"amd64","pin":"x"}`
		if err := os.WriteFile(filepath.Join(receipts, c.Name+".json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got := checkVersionMatrix(layout)
	if got.OK {
		t.Error("a node running unpinned component versions passed the matrix check")
	}
	if !strings.Contains(got.Detail, "0.0.1-wrong") {
		t.Errorf("detail %q does not name the drifted version", got.Detail)
	}
}

// Every distribution ships fuse.conf with the option commented out, and
// treating that as set leaves every S3 volume failing at deploy time.
func TestFuseCheckReportsAProblemWithAFix(t *testing.T) {
	if goruntime.GOOS != "linux" {
		// On anything else the check reports "not checked", which is the one
		// warning with nothing to suggest.
		t.Skip("FUSE is a Linux concern")
	}
	got := checkFUSE()
	if got.Warn && got.Fix == "" {
		t.Error("the fuse check warns without saying what to do about it")
	}
	// Never a hard failure: a node that mounts no S3 volume is fine without it.
	if !got.OK {
		t.Error("a missing FUSE setup failed the node; it should warn")
	}
}
