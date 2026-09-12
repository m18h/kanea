package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/provision"
)

func TestParseAptSimulation(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []api.PackageUpdate
	}{
		{
			name: "an upgrade with an installed version and a security origin",
			out:  "Inst libssl3 [3.0.16-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])\n",
			want: []api.PackageUpdate{{
				Name: "libssl3", Installed: "3.0.16-1~deb12u1", Candidate: "3.0.17-1~deb12u2",
				Origin: "Debian-Security:12/stable-security", Security: true,
			}},
		},
		{
			name: "a newly pulled-in package has no installed version",
			out:  "Inst linux-image-6.1.0-40-amd64 (6.1.148-1 Debian:12.12/stable [amd64])\n",
			want: []api.PackageUpdate{{
				Name: "linux-image-6.1.0-40-amd64", Candidate: "6.1.148-1",
				Origin: "Debian:12.12/stable",
			}},
		},
		{
			name: "an origin with spaces survives whole",
			out:  "Inst tzdata [2025a-0+deb12u1] (2025b-0+deb12u1 Debian:12.12/stable, Debian-Security:12/stable-security [all])\n",
			want: []api.PackageUpdate{{
				Name: "tzdata", Installed: "2025a-0+deb12u1", Candidate: "2025b-0+deb12u1",
				Origin: "Debian:12.12/stable, Debian-Security:12/stable-security", Security: true,
			}},
		},
		{
			name: "Conf, Remv and the simulation preamble are not pending updates",
			out: "NOTE: This is only a simulation!\n" +
				"Reading package lists...\n" +
				"Inst curl [7.88.1-10+deb12u12] (7.88.1-10+deb12u14 Debian:12.12/stable [amd64])\n" +
				"Conf curl (7.88.1-10+deb12u14 Debian:12.12/stable [amd64])\n" +
				"Remv old-package [1.0-1]\n",
			want: []api.PackageUpdate{{
				Name: "curl", Installed: "7.88.1-10+deb12u12", Candidate: "7.88.1-10+deb12u14",
				Origin: "Debian:12.12/stable",
			}},
		},
		{
			name: "nothing pending parses to nothing",
			out:  "Reading package lists...\nBuilding dependency tree...\n0 upgraded, 0 newly installed.\n",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAptSimulation([]byte(tt.out))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAptSimulation:\n got %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

// testInspector is a hostInspector aimed at a temp root with fake seams.
func testInspector(t *testing.T, aptOut string, aptMissing bool) *hostInspector {
	t.Helper()
	root := t.TempDir()
	return &hostInspector{
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		root:   root,
		layout: provision.Layout{Prefix: filepath.Join(root, "prefix")},
		lookPath: func(string) (string, error) {
			if aptMissing {
				return "", errors.New("not found")
			}
			return "/usr/bin/apt-get", nil
		},
		runCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(aptOut), nil
		},
	}
}

func writeHostFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInspectReadsTheHost(t *testing.T) {
	h := testInspector(t,
		"Inst libssl3 [3.0.16-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])\n"+
			"Inst curl [7.88.1-10+deb12u12] (7.88.1-10+deb12u14 Debian:12.12/stable [amd64])\n",
		false)
	writeHostFile(t, h.root, "etc/os-release",
		"NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")
	writeHostFile(t, h.root, "proc/sys/kernel/osrelease", "6.1.0-37-amd64\n")
	writeHostFile(t, h.root, "run/reboot-required", "*** System restart required ***\n")
	writeHostFile(t, h.root, "var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_InRelease", "x")

	view, err := h.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	osv := view.OS
	if osv.Name != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("name = %q", osv.Name)
	}
	if osv.Kernel != "6.1.0-37-amd64" {
		t.Errorf("kernel = %q", osv.Kernel)
	}
	if osv.PackageManager != "apt" {
		t.Errorf("package manager = %q", osv.PackageManager)
	}
	if osv.PendingTotal == nil || *osv.PendingTotal != 2 {
		t.Errorf("pending total = %v, want 2", osv.PendingTotal)
	}
	if osv.SecurityTotal == nil || *osv.SecurityTotal != 1 {
		t.Errorf("security total = %v, want 1", osv.SecurityTotal)
	}
	if osv.RebootRequired == nil || !*osv.RebootRequired {
		t.Errorf("reboot = %v, want true", osv.RebootRequired)
	}
	if osv.ListsRefreshedAt == nil {
		t.Error("lists refreshed = nil; a fetched list has a time")
	}
	// The matrix comes from the embedded manifest; with no receipts every
	// component is pinned-but-unknown, never invented.
	if len(view.Components) == 0 {
		t.Fatal("no components; the embedded manifest always has them")
	}
	for _, c := range view.Components {
		if c.Installed != "" {
			t.Errorf("component %s installed = %q with no receipt", c.Name, c.Installed)
		}
		if c.Pinned == "" {
			t.Errorf("component %s has no pin", c.Name)
		}
	}
}

func TestInspectWithoutAptSaysUnsupported(t *testing.T) {
	// "No data" is never zero (§9.2): a node this probe cannot read answers
	// unknown, not a page of reassuring zeroes.
	h := testInspector(t, "", true)
	view, err := h.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	osv := view.OS
	if osv.PackageManager != "unsupported" {
		t.Errorf("package manager = %q, want unsupported", osv.PackageManager)
	}
	if osv.PendingTotal != nil || osv.SecurityTotal != nil {
		t.Errorf("totals = %v/%v, want absent", osv.PendingTotal, osv.SecurityTotal)
	}
	if osv.RebootRequired != nil {
		t.Errorf("reboot = %v, want absent: no apt means no flag convention", osv.RebootRequired)
	}
	if osv.ListsRefreshedAt != nil {
		t.Errorf("lists refreshed = %v, want absent", osv.ListsRefreshedAt)
	}
}

func TestInspectAptFailureLeavesCountsUnknown(t *testing.T) {
	h := testInspector(t, "", false)
	h.runCommand = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("exec: exit status 100")
	}
	view, err := h.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if view.OS.PendingTotal != nil || view.OS.SecurityTotal != nil {
		t.Errorf("totals = %v/%v, want absent after a failed probe",
			view.OS.PendingTotal, view.OS.SecurityTotal)
	}
	if view.OS.PackageManager != "apt" {
		t.Errorf("package manager = %q; the family is known even when the probe fails", view.OS.PackageManager)
	}
}

func TestComponentViewsReadTheReceipts(t *testing.T) {
	h := testInspector(t, "", true)
	manifest, err := provision.Load()
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	first := manifest.All()[0]
	writeHostFile(t, h.root, filepath.Join("prefix", ".receipts", first.Name+".json"),
		`{"name":"`+first.Name+`","version":"0.0.0-test","kind":"`+string(first.Kind)+`","arch":"amd64","pin":"x"}`)

	view, err := h.Inspect(context.Background())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	var got api.ComponentView
	for _, c := range view.Components {
		if c.Name == first.Name {
			got = c
		}
	}
	if got.Installed != "0.0.0-test" {
		t.Errorf("installed = %q, want the receipt's 0.0.0-test", got.Installed)
	}
	if got.Pinned != first.Version {
		t.Errorf("pinned = %q, want the manifest's %s", got.Pinned, first.Version)
	}
}
