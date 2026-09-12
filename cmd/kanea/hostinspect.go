package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/provision"
)

// hostInspector implements internal/api.HostInspector (PRD v1.108): the OS's
// own pending updates and the §5.2.12 component matrix, local reads only. It
// never refreshes a package list and never installs anything - a control this
// daemon cannot enforce (a dpkg prompt, a held package) is not offered, so
// the surface is read facts, and the dashboard names the command to run on
// the node instead.
type hostInspector struct {
	log *slog.Logger
	// root prefixes every absolute path read: "/" in production, a tempdir in
	// tests.
	root   string
	layout provision.Layout
	// lookPath and runCommand are seam-shaped for tests; the real ones are
	// exec's.
	lookPath   func(file string) (string, error)
	runCommand func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func newHostInspector(log *slog.Logger) *hostInspector {
	return &hostInspector{
		log: log, root: "/", layout: provision.DefaultLayout(),
		lookPath: exec.LookPath,
		runCommand: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output() // #nosec G204: a fixed argv on a resolved binary
		},
	}
}

// inspectTimeout bounds the whole probe: one exec of the package manager's
// simulation plus file reads, all local.
const inspectTimeout = 20 * time.Second

// maxPendingShown bounds the pending list in the response; PendingTotal
// carries the real count either way.
const maxPendingShown = 100

// Inspect answers with what it could read. A part that cannot answer stays
// absent (§9.2: no data is never zero) rather than failing the parts that
// can, so the error return is reserved for nothing today and kept for the
// interface's sake.
func (h *hostInspector) Inspect(ctx context.Context) (api.UpdatesView, error) {
	ctx, cancel := context.WithTimeout(ctx, inspectTimeout)
	defer cancel()
	return api.UpdatesView{
		OS:         h.osView(ctx),
		Components: h.componentViews(),
	}, nil
}

func (h *hostInspector) osView(ctx context.Context) api.OSView {
	view := api.OSView{
		Name:   osReleaseName(filepath.Join(h.root, "etc/os-release")),
		Kernel: readTrimmed(filepath.Join(h.root, "proc/sys/kernel/osrelease")),
	}

	// The apt family is the v1 probe; anything else says so rather than
	// answering zeroes nobody measured.
	if _, err := h.lookPath("apt-get"); err != nil {
		view.PackageManager = "unsupported"
		return view
	}
	view.PackageManager = "apt"

	// The reboot flag and list freshness are answerable even when the
	// simulation below fails; on the apt family an absent flag file means no
	// reboot is pending, which is a measured no, not a gap.
	reboot := fileExists(filepath.Join(h.root, "run/reboot-required"))
	view.RebootRequired = &reboot
	if t, ok := newestListTime(filepath.Join(h.root, "var/lib/apt/lists")); ok {
		view.ListsRefreshedAt = &t
	}

	// --simulate resolves against the lists already on disk: no lock, no
	// network, no root. dist-upgrade rather than upgrade so a kernel that
	// pulls a new package in is counted like apt's own full-upgrade counts it.
	out, err := h.runCommand(ctx, "apt-get", "--simulate", "--quiet", "dist-upgrade")
	if err != nil {
		h.log.Warn("the pending-updates probe failed; the counts stay unknown", "error", err)
		return view
	}
	pending := parseAptSimulation(out)
	total, security := len(pending), 0
	for _, p := range pending {
		if p.Security {
			security++
		}
	}
	if len(pending) > maxPendingShown {
		pending = pending[:maxPendingShown]
	}
	view.Pending, view.PendingTotal, view.SecurityTotal = pending, &total, &security
	return view
}

// parseAptSimulation reads the "Inst" lines out of `apt-get --simulate`:
//
//	Inst libssl3 [3.0.16-1~deb12u1] (3.0.17-1~deb12u2 Debian-Security:12/stable-security [amd64])
//	Inst linux-image-6.1.0-40-amd64 (6.1.148-1 Debian:12.12/stable [amd64])
//
// The bracketed installed version is absent for a package the upgrade newly
// pulls in; Conf and Remv lines are not pending updates and are skipped.
func parseAptSimulation(out []byte) []api.PackageUpdate {
	var pending []api.PackageUpdate
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "Inst" {
			continue
		}
		p := api.PackageUpdate{Name: fields[1]}
		rest := fields[2:]
		if strings.HasPrefix(rest[0], "[") {
			p.Installed = strings.Trim(rest[0], "[]")
			rest = rest[1:]
		}
		if len(rest) == 0 || !strings.HasPrefix(rest[0], "(") {
			continue
		}
		p.Candidate = strings.TrimPrefix(rest[0], "(")
		// Between the candidate and the closing "[arch])" sits the origin,
		// which may itself contain spaces ("Debian-Security:12/stable-security").
		var origin []string
		for _, f := range rest[1:] {
			if strings.HasPrefix(f, "[") {
				break
			}
			origin = append(origin, f)
		}
		p.Origin = strings.Join(origin, " ")
		p.Security = strings.Contains(strings.ToLower(p.Origin), "security")
		pending = append(pending, p)
	}
	return pending
}

// componentViews is checkVersionMatrix's comparison served as data: the
// embedded manifest's pins against the receipt files, never an exec.
func (h *hostInspector) componentViews() []api.ComponentView {
	manifest, err := provision.Load()
	if err != nil {
		h.log.Warn("the component manifest is unreadable; the matrix stays unknown", "error", err)
		return nil
	}
	installer := &provision.Installer{Layout: h.layout}
	views := make([]api.ComponentView, 0, len(manifest.Components))
	for _, c := range manifest.All() {
		v := api.ComponentView{Name: c.Name, Pinned: c.Version}
		if installed, _, ok := installer.Installed(c.Name); ok {
			v.Installed = installed
		}
		views = append(views, v)
	}
	return views
}

// osReleaseName is os-release's PRETTY_NAME, empty when the file cannot say.
func osReleaseName(path string) string {
	raw, err := os.ReadFile(path) // #nosec G304: a path this file composed
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		value, found := strings.CutPrefix(line, "PRETTY_NAME=")
		if !found {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"`)
	}
	return ""
}

func readTrimmed(path string) string {
	raw, err := os.ReadFile(path) // #nosec G304: a path this file composed
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// newestListTime is the mtime of the freshest file under apt's lists
// directory: when the node last actually fetched indexes. The lock file
// moves on every apt invocation and is excluded; partial/ is a directory and
// skipped with the rest.
func newestListTime(dir string) (time.Time, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, false
	}
	var newest time.Time
	for _, e := range entries {
		if e.IsDir() || e.Name() == "lock" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest.UTC(), !newest.IsZero()
}
