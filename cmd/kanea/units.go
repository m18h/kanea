package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/m18h/kanea/internal/edge"
)

// systemd units (PRD §5.2.11, §20 M10).
//
// The cgroup layout is the point, not the service files. Constraint #11 says
// the control plane has a kernel-guaranteed memory floor and workloads have a
// ceiling, and neither is something Go can arrange for itself — `memory.min`
// and `OOMScoreAdjust` are systemd's to set. A Kanea installed without these
// units runs, and the first time the node is under memory pressure the OOM
// killer picks whatever is largest, which is usually kanead.
//
// Written as files rather than embedded and applied, because an operator has to
// be able to read and change them. They are configuration, not internals.

// unitOptions describes the install the units are written for.
type unitOptions struct {
	dir     string
	dataDir string
	logDir  string
	// reserve is the control plane's memory floor, as a systemd size.
	reserve string
	// binary is the absolute path to the kanea executable.
	binary string
}

// unitFile is one file to write.
type unitFile struct {
	name    string
	content string
}

// writeUnits renders and installs the units.
func writeUnits(o *out, opts unitOptions) error {
	files := []unitFile{
		{"kanea.slice", kaneaSlice(opts)},
		{"kanea-workloads.slice", workloadSlice()},
		{"kanead.service", kaneadService(opts)},
		{"kanea-edge.service", edgeService(opts)},
	}

	// #nosec G301 — /etc/systemd/system is 0755 on every distribution, and
	// systemd is not the only thing that reads it: `systemctl cat` runs as the
	// invoking user. The units carry no secrets, which is exactly why R3 keeps
	// credentials out of them.
	if err := os.MkdirAll(opts.dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", opts.dir, err)
	}
	for _, file := range files {
		path := filepath.Join(opts.dir, file.name)
		// 0644: systemd units are read by systemd and by whoever is debugging
		// them. They carry no secrets — credentials are `secret:` references
		// resolved at runtime (R3), which is exactly why that rule exists.
		if err := os.WriteFile(path, []byte(file.content), 0o644); err != nil { // #nosec G306 — unit files are world-readable by design
			return fmt.Errorf("write %s: %w", path, err)
		}
		o.printf("Wrote %s\n", path)
	}
	return nil
}

// kaneaSlice is the control plane's cgroup.
//
// MemoryMin is the load-bearing line. It is a *protection*, not a limit: the
// kernel reclaims from other cgroups before it reclaims from this one, which is
// what makes "kanead survives a workload eating the node" a guarantee rather
// than a hope. §5.2.11 sets the default at 1 GiB.
func kaneaSlice(opts unitOptions) string {
	return heredoc(`
		[Unit]
		Description=Kanea control plane
		Documentation=https://github.com/m18h/kanea
		Before=slices.target

		[Slice]
		# A kernel-guaranteed floor, not a limit (PRD §5.2.11, AGENTS.md #11).
		# The control plane is reclaimed from last, so a workload that takes the
		# node does not take kanead with it.
		MemoryMin=` + opts.reserve + `
		MemoryLow=` + opts.reserve + `
	`)
}

// workloadSlice is every alloc's parent cgroup.
//
// No MemoryMax here: the ceiling is total RAM minus the reserve, and only the
// node knows what that is. kanead sets it at startup on the live cgroup, which
// is why this file declares the slice and not the number.
func workloadSlice() string {
	return heredoc(`
		[Unit]
		Description=Kanea workloads
		Documentation=https://github.com/m18h/kanea
		Before=slices.target

		[Slice]
		# The ceiling (total RAM minus the control-plane reserve) is computed and
		# applied by kanead at startup: it depends on how much memory this node
		# has, which a static file cannot know.
		#
		# Every alloc is created under this slice, so a runaway workload is
		# bounded by the sum rather than by its own limit alone.
	`)
}

// kaneadService is the control-plane daemon.
func kaneadService(opts unitOptions) string {
	return heredoc(`
		[Unit]
		Description=Kanea control plane (kanead)
		Documentation=https://github.com/m18h/kanea
		After=network-online.target containerd.service
		Wants=network-online.target
		# Not a hard dependency: kanead retries containerd and reports it, which
		# is more useful than refusing to start.
		After=cilium.service

		[Service]
		# Type=exec, not notify: kanead sends no sd_notify readiness message, and
		# systemd would wait for one that never comes and then kill the service.
		# exec still catches the common failure — a missing or unexecutable
		# binary — which Type=simple would report as a successful start.
		Type=exec
		ExecStart=` + opts.binary + ` agent --data-dir ` + opts.dataDir + ` --log-dir ` + opts.logDir + `
		Restart=always
		RestartSec=5s
		Slice=kanea.slice

		# The other half of constraint #11: when the kernel does have to choose,
		# it should not choose the control plane.
		OOMScoreAdjust=-900

		# kanead needs root: it creates network namespaces, writes cgroups and
		# talks to containerd's socket. What it does not need is the ability to
		# be surprised by its own filesystem.
		NoNewPrivileges=yes
		ProtectSystem=strict
		ProtectHome=yes
		PrivateTmp=yes
		ReadWritePaths=` + opts.dataDir + ` ` + opts.logDir + ` /run /sys/fs/cgroup /var/run

		# A control plane restart must not take the workloads with it.
		KillMode=process
		TimeoutStopSec=30s

		[Install]
		WantedBy=multi-user.target
	`)
}

// edgeService is the ingress proxy.
//
// The two projection paths are written out rather than left to the defaults,
// because they are the whole interface between this process and kanead and an
// operator has to be able to see and change them. They are spelled with the
// same constants the daemon publishes to and the edge reads from, so the unit
// cannot come to disagree with the code about where the files live.
//
// A separate unit because it is a separate process, from day one (§18 rule 8):
// north-south traffic survives a control-plane restart, an upgrade, or a crash.
// Nothing here depends on kanead being up.
func edgeService(opts unitOptions) string {
	return heredoc(`
		[Unit]
		Description=Kanea edge proxy (kanea-edge)
		Documentation=https://github.com/m18h/kanea
		After=network-online.target
		Wants=network-online.target
		# Deliberately not After=kanead.service. The edge reads a route snapshot
		# from disk and serves traffic whether or not the control plane is up —
		# that separation is the whole reason it is its own process (PRD §5.2.6).

		[Service]
		# See kanead.service: no sd_notify, so no Type=notify.
		Type=exec
		ExecStart=` + opts.binary + ` edge --routes ` + edge.DefaultSnapshotPath +
		` --certs ` + edge.DefaultBundlePath + `
		Restart=always
		RestartSec=2s
		Slice=kanea.slice
		OOMScoreAdjust=-800

		# Binding privileged ports is all the privilege it needs, and it drops
		# the rest. The ambient capability lives in the effective set for the
		# process's lifetime, so a bind on a published port below 1024 (§7.2.2)
		# an hour after startup is exactly as permitted as :443 at t=0 — there is
		# nothing to add here when a spec asks for one.
		AmbientCapabilities=CAP_NET_BIND_SERVICE
		CapabilityBoundingSet=CAP_NET_BIND_SERVICE
		RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
		NoNewPrivileges=yes
		ProtectSystem=strict
		ProtectHome=yes
		PrivateTmp=yes
		# No ReadWritePaths: the edge writes nothing. ProtectSystem=strict makes
		# the filesystem read-only, not invisible, so the two projections above
		# are still readable.

		[Install]
		WantedBy=multi-user.target
	`)
}

// heredoc strips the indentation a raw string literal picks up from being
// written inside a Go function, so the unit files do not carry it.
//
// systemd tolerates leading whitespace in some places and not others, and a
// unit that is subtly wrong fails at `systemctl daemon-reload` rather than
// anywhere useful. The trailing line matters too: the closing backtick sits one
// indent in, which leaves a whitespace-only last line.
func heredoc(body string) string {
	lines := strings.Split(strings.Trim(body, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, "\t")
	}
	return strings.Join(lines, "\n") + "\n"
}
