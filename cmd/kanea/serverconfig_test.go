package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/m18h/kanea/internal/nodeconfig"
)

func writeServerConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kanea.hcl")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerConfigProbesTheWellKnownPath(t *testing.T) {
	path := writeServerConfig(t, `storage { allowed_host_paths = ["/srv"] }`)
	cfg, err := serverConfigForRun("", "", "", path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AllowedHostPaths) != 1 || cfg.AllowedHostPaths[0] != "/srv" {
		t.Fatalf("AllowedHostPaths = %v", cfg.AllowedHostPaths)
	}
}

func TestServerConfigAbsentIsOff(t *testing.T) {
	cfg, err := serverConfigForRun("", "", "", filepath.Join(t.TempDir(), "kanea.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != "" || cfg.AllowedHostPaths != nil {
		t.Fatalf("an absent well-known file must be off, got %+v", cfg)
	}
}

func TestServerConfigOffIgnoresAPresentFile(t *testing.T) {
	path := writeServerConfig(t, `this is not hcl at all {{{`)
	cfg, err := serverConfigForRun("off", "", "", path)
	if err != nil {
		t.Fatalf("--config off must not read the file: %v", err)
	}
	if cfg.Path != "" {
		t.Fatalf("got %+v, want the zero config", cfg)
	}
}

func TestServerConfigExplicitPathMustExist(t *testing.T) {
	if _, err := serverConfigForRun(filepath.Join(t.TempDir(), "x.hcl"), "", "", ""); err == nil {
		t.Fatal("--config naming a missing file must be fatal")
	}
}

func TestServerConfigMalformedProbedFileIsFatal(t *testing.T) {
	path := writeServerConfig(t, `storage {`)
	if _, err := serverConfigForRun("", "", "", path); err == nil {
		t.Fatal("a malformed probed file must refuse startup, not half-load")
	}
}

// The upgrade-with-flags promise: a unit carrying both policy flags today must
// behave byte-identically after the upgrade, whatever sits at the well-known
// path — nothing would read the file, so it cannot be allowed to refuse boot.
func TestServerConfigSkipsTheProbeWhenBothHalvesAreFlagged(t *testing.T) {
	path := writeServerConfig(t, `garbage {{{`)
	cfg, err := serverConfigForRun("", "/srv", "/etc/pt.hcl", path)
	if err != nil {
		t.Fatalf("a file nothing reads refused startup: %v", err)
	}
	if cfg.Path != "" {
		t.Fatalf("the file was read: %+v", cfg)
	}
	// An explicit --config, though, is an instruction to read it.
	if _, err := serverConfigForRun(path, "/srv", "/etc/pt.hcl", path); err == nil {
		t.Fatal("--config is explicit; a malformed file must still be fatal")
	}
}

func TestResolveHostPathsPrecedence(t *testing.T) {
	cfg := &nodeconfig.Config{AllowedHostPaths: []string{"/from-file"}, Path: "/etc/kanea/kanea.hcl"}

	paths, source := resolveHostPaths("", cfg)
	if len(paths) != 1 || paths[0] != "/from-file" || source != cfg.Path {
		t.Fatalf("unset flag must read the file: %v %q", paths, source)
	}

	paths, source = resolveHostPaths("/a,/b", cfg)
	if len(paths) != 2 || paths[0] != "/a" || source != "--allowed-host-paths" {
		t.Fatalf("a set flag must win: %v %q", paths, source)
	}

	paths, source = resolveHostPaths("off", cfg)
	if paths != nil || source != "off" {
		t.Fatalf("off must disable regardless of the file: %v %q", paths, source)
	}
}

func TestResolvePassthroughPathPrecedence(t *testing.T) {
	grantFile := writeServerConfig(t, ``)
	cfg := &nodeconfig.Config{HasGrants: true, Path: "/etc/kanea/kanea.hcl"}

	path, source, err := resolvePassthroughPath("", cfg)
	if err != nil || path != cfg.Path || source != cfg.Path {
		t.Fatalf("unset flag must read grants from the server config: %q %q %v", path, source, err)
	}

	path, source, err = resolvePassthroughPath("", &nodeconfig.Config{})
	if err != nil || path != "" || source != "" {
		t.Fatalf("no file and no flag must mean no grants: %q %q %v", path, source, err)
	}

	path, source, err = resolvePassthroughPath(grantFile, cfg)
	if err != nil || path != grantFile || source != "--passthrough-config" {
		t.Fatalf("a set flag must win: %q %q %v", path, source, err)
	}

	path, source, err = resolvePassthroughPath("off", cfg)
	if err != nil || path != "" || source != "off" {
		t.Fatalf("off must disable regardless of the file: %q %q %v", path, source, err)
	}
}

// The trust check does not weaken because the path arrived by argv: a
// group-writable grants file is the same hole flagged or probed.
func TestResolvePassthroughPathRefusesAnUntrustedFlaggedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pt.hcl")
	if err := os.WriteFile(path, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolvePassthroughPath(path, &nodeconfig.Config{}); err == nil {
		t.Fatal("a world-writable grants file must be refused")
	}
}

// createLayout gained the config directory in v1.51: the probed kanea.hcl
// needs somewhere to be created, and init is what makes the directories.
func TestCreateLayoutMakesTheConfDir(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	logDir := filepath.Join(base, "logs")
	confDir := filepath.Join(base, "etc", "kanea")
	if err := createLayout(newOut(), dataDir, logDir, confDir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(confDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Fatalf("conf dir mode = %04o, want 0755", perm)
	}
}
