package provision

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// systemd units and configuration for the host components (PRD §5.2.12).
//
// Since v1.30 these are Kanea's own units, so each simply declares
// Slice=kanea.slice — you do not need a drop-in for a unit you wrote. That is
// how constraint #11's memory floor reaches containerd, etcd, cilium and
// buildkitd; the drop-in machinery §5.2.11 describes survives only for an
// adopted external containerd, whose unit belongs to the distribution.
//
// Written as files rather than applied through some API, for the reason
// cmd/kanea/units.go gives: an operator has to be able to read and change
// them. They are configuration, not internals.

// ConfigFile is one rendered file and where it goes.
type ConfigFile struct {
	Path string
	Body string
	Mode os.FileMode
}

// SocketPath is Kanea's containerd socket — deliberately not the
// distribution's /run/containerd/containerd.sock, which belongs to whatever
// else on the node is using it.
//
// ContainerdSocket overrides it when an existing daemon was adopted, so
// everything downstream asks the layout rather than deciding for itself.
func (l Layout) SocketPath() string {
	if l.ContainerdSocket != "" {
		return l.ContainerdSocket
	}
	return filepath.Join(l.RunDir, "containerd.sock")
}

// EtcdEndpoint is the loopback address cilium uses as its kvstore.
const EtcdEndpoint = "127.0.0.1:2379"

// Files returns every unit and config file for the selected components.
//
// Components are asked for by name rather than rendered wholesale, so
// `kanea install --only containerd` does not write a cilium unit for a cilium
// that is not there — a unit systemd would then fail to start on every boot.
func (l Layout) Files(components []*Component, binary, reserve string) []ConfigFile {
	want := make(map[string]bool, len(components))
	for _, c := range components {
		want[c.Name] = true
	}

	var out []ConfigFile
	if want["containerd"] {
		out = append(out,
			ConfigFile{filepath.Join(l.ConfDir, "containerd", "config.toml"), l.containerdConfig(), 0o644},
			ConfigFile{filepath.Join(l.UnitDir, "kanea-containerd.service"), l.containerdUnit(), 0o644},
		)
	}
	if want["cni-plugins"] || want["cilium"] {
		out = append(out,
			ConfigFile{filepath.Join(l.ConfDir, "cni", "net.d", "05-cilium.conflist"), ciliumConflist(), 0o644},
		)
	}
	if want["etcd"] {
		out = append(out, ConfigFile{filepath.Join(l.UnitDir, "kanea-etcd.service"), l.etcdUnit(), 0o644})
	}
	if want["cilium"] {
		out = append(out, ConfigFile{filepath.Join(l.UnitDir, "kanea-cilium.service"), l.ciliumUnit(binary), 0o644})
	}
	if want["buildkit"] {
		out = append(out, ConfigFile{filepath.Join(l.UnitDir, "kanea-buildkit.service"), l.buildkitUnit(), 0o644})
	}
	_ = reserve // the floor lives on kanea.slice, which cmd/kanea owns
	return out
}

// DistroContainerdSocket is where a distribution's containerd listens. Kanea
// never installs here; this is only for adopting one that already exists.
const DistroContainerdSocket = "/run/containerd/containerd.sock"

// AdoptedContainerdDropIn extends the control plane's memory floor to a
// containerd Kanea did not install (`--containerd external`).
//
// This is the one case §5.2.11's drop-in language still describes. For a unit
// Kanea wrote, `Slice=kanea.slice` goes in the unit — you do not need a
// drop-in for a file you own. For the distribution's unit you do, because
// editing it would put Kanea's changes in the path of the next package
// upgrade, which would silently discard them.
func AdoptedContainerdDropIn(unitDir string) ConfigFile {
	return ConfigFile{
		Path: filepath.Join(unitDir, "containerd.service.d", "10-kanea-slice.conf"),
		Mode: 0o644,
		Body: heredoc(`
			# Written by kanea (PRD §5.2.11, §5.2.12).
			#
			# This containerd is not Kanea's — it was adopted with
			# --containerd external. The drop-in extends the control plane's
			# memory floor to it without editing a unit the distribution owns
			# and will replace on its next upgrade.
			#
			# Removing this file is safe: it costs the guarantee in constraint
			# #11 that a runaway workload cannot take the runtime with it.
			[Service]
			Slice=kanea.slice
			OOMScoreAdjust=-900
		`),
	}
}

// WriteFiles installs the rendered files.
func WriteFiles(files []ConfigFile) error {
	for _, f := range files {
		if err := writeFileAtomic(f.Path, bytes.NewReader([]byte(f.Body)), f.Mode); err != nil {
			return err
		}
	}
	return nil
}

// containerdConfig is containerd's config.toml.
//
// Config version 3 (containerd 2.x). Every path is Kanea's: a containerd that
// shared the distribution's root would share its images and its snapshots, and
// "Kanea installed itself" would become "Kanea took over your containers".
func (l Layout) containerdConfig() string {
	return heredoc(`
		version = 3

		root  = "` + filepath.Join(l.DataDir, "containerd") + `"
		state = "` + filepath.Join(l.RunDir, "containerd") + `"

		[grpc]
		  address = "` + l.SocketPath() + `"

		# The metrics endpoint the autoscaler's containerd scraper reads
		# (PRD §9.1). M0 found 47 metric families per task here, which is why
		# that scraper streams and allowlists rather than parsing the lot.
		[metrics]
		  address = "127.0.0.1:1338"

		[plugins]
		  [plugins.'io.containerd.cri.v1.runtime']
		    # Kanea calls CNI itself, in the order §5.2.5 fixes: netns, CNI ADD,
		    # label PATCH, then task start. CRI is not in the path at all.
		    [plugins.'io.containerd.cri.v1.runtime'.cni]
		      bin_dir  = "` + l.CNIBinDir() + `"
		      conf_dir = "` + filepath.Join(l.ConfDir, "cni", "net.d") + `"

		  [plugins.'io.containerd.runtime.v2.task']
		    platforms = ["linux/amd64", "linux/arm64"]
	`)
}

// containerdUnit supervises Kanea's containerd.
func (l Layout) containerdUnit() string {
	return heredoc(`
		[Unit]
		Description=containerd (Kanea)
		Documentation=https://github.com/m18h/kanea
		After=network-online.target
		Wants=network-online.target

		[Service]
		Type=notify
		Delegate=yes
		ExecStart=` + l.BinDir() + `/containerd --config ` + filepath.Join(l.ConfDir, "containerd", "config.toml") + `
		Restart=always
		RestartSec=5s
		Slice=kanea.slice

		# The control plane's floor reaches containerd because the unit is ours
		# to write (PRD §5.2.11, constraint #11).
		OOMScoreAdjust=-900

		# containerd's own recommendations: it forks shims that must outlive a
		# containerd restart, so the process is killed and its children are not.
		KillMode=process
		LimitNOFILE=1048576
		TasksMax=infinity

		# runc needs to move processes between cgroups and mount filesystems, so
		# the usual sandboxing does not apply here the way it does to kanead.
		# The isolation that matters for workloads is the one they run under.
		[Install]
		WantedBy=multi-user.target
	`)
}

// etcdUnit is Cilium's kvstore.
//
// Loopback only, and a single node. This is derived state (§18 rule 9): it is
// rebuilt from the Store, it is never backed up and it is never restored, so
// there is nothing here to protect with authentication that a bind address
// does not already protect.
func (l Layout) etcdUnit() string {
	return heredoc(`
		[Unit]
		Description=etcd for standalone Cilium (Kanea)
		Documentation=https://github.com/m18h/kanea
		After=network-online.target
		Wants=network-online.target

		[Service]
		Type=notify
		ExecStart=` + l.BinDir() + `/etcd \
		  --name=kanea \
		  --data-dir=` + filepath.Join(l.DataDir, "etcd") + ` \
		  --listen-client-urls=http://` + EtcdEndpoint + ` \
		  --advertise-client-urls=http://` + EtcdEndpoint + ` \
		  --listen-peer-urls=http://127.0.0.1:2380 \
		  --initial-advertise-peer-urls=http://127.0.0.1:2380 \
		  --initial-cluster=kanea=http://127.0.0.1:2380 \
		  --initial-cluster-state=new \
		  --auto-compaction-retention=1
		Restart=always
		RestartSec=3s
		Slice=kanea.slice
		OOMScoreAdjust=-900
		LimitNOFILE=65536

		[Install]
		WantedBy=multi-user.target
	`)
}

// ciliumUnit runs cilium-agent as a containerd task.
//
// ExecStart is kanea itself rather than a shell wrapper: `kanea supervise
// cilium` creates the task through internal/runtime, which is what lets the
// task's cgroup be placed under kanea.slice. A wrapper would also mean the
// "container orchestration in one binary" claim quietly acquired a second file.
//
// Deliberately not After=kanead.service. The dataplane is what carries traffic
// and it must not depend on the control plane's lifecycle — the same rule
// cmd/kanea/units.go applies to kanea-edge, for the same reason.
func (l Layout) ciliumUnit(binary string) string {
	node, cluster := l.Networking()
	return heredoc(`
		[Unit]
		Description=cilium-agent (Kanea)
		Documentation=https://github.com/m18h/kanea
		After=kanea-containerd.service kanea-etcd.service
		Requires=kanea-containerd.service
		# The kvstore is a hard requirement in practice but a soft one here:
		# cilium retries it, and a start that fails because etcd was two seconds
		# late is worse than one that waits.
		Wants=kanea-etcd.service

		[Service]
		Type=exec
		ExecStart=` + binary + ` supervise cilium --node-cidr ` + node +
		` --cluster-cidr ` + cluster + `
		Restart=always
		RestartSec=5s
		Slice=kanea.slice
		OOMScoreAdjust=-900

		# The agent is a privileged host-network task: it loads eBPF programs,
		# writes /sys/fs/bpf and programs netfilter. That privilege is the
		# dataplane's, not a workload's — every alloc still runs with ALL
		# capabilities dropped (§14).
		Delegate=yes
		KillMode=mixed
		TimeoutStopSec=30s

		[Install]
		WantedBy=multi-user.target
	`)
}

// buildkitUnit is the rootless build daemon (PRD §5.2.11, §10.2).
//
// The socket lives in the daemon user's $HOME and *not* under a copy-up'd
// /run: rootlesskit gives the daemon a namespace-private tmpfs there, so a
// socket in /run is invisible to every client outside the namespace. M0 spike
// ④ found that the expensive way.
func (l Layout) buildkitUnit() string {
	home := filepath.Join(l.DataDir, "buildkit")
	return heredoc(`
		[Unit]
		Description=rootless buildkitd (Kanea)
		Documentation=https://github.com/m18h/kanea
		After=network-online.target
		Wants=network-online.target

		[Service]
		Type=exec
		User=` + BuildkitUser + `
		Environment=HOME=` + home + `
		Environment=XDG_RUNTIME_DIR=` + filepath.Join(home, "run") + `
		Environment=PATH=` + l.BinDir() + `:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
		# --net=host keeps a node-local registry reachable (M0 spike ④).
		ExecStart=` + l.BinDir() + `/rootlesskit \
		  --net=host \
		  --copy-up=/etc \
		  --copy-up=/run \
		  ` + l.BinDir() + `/buildkitd \
		    --addr unix://` + filepath.Join(home, "run", "buildkitd.sock") + ` \
		    --oci-worker-no-process-sandbox \
		    --oci-max-parallelism 2
		Restart=always
		RestartSec=5s
		Slice=kanea.slice

		# Build isolation is collective, not per build (§10.2): one cap on the
		# unit, and a second concurrent build shares the first's budget. That is
		# why the runner serialises and refuses when full rather than blocking.
		OOMScoreAdjust=-500

		[Install]
		WantedBy=multi-user.target
	`)
}

// BuildkitUser is the unprivileged account buildkitd runs as.
const BuildkitUser = "kanea-buildkit"

// ciliumConflist is the CNI configuration Kanea's containerd hands to the
// Cilium plugin.
//
// It carries no subnet and needs none: there is deliberately no `ipam` block,
// because IPAM is delegated to the agent (`--ipam=cluster-pool`). The node and
// cluster CIDRs reach cilium through its own flags in the unit, so there is
// nothing here to plumb a subnet into.
func ciliumConflist() string {
	return heredoc(`
		{
		  "name": "kanea",
		  "cniVersion": "1.0.0",
		  "plugins": [
		    {
		      "type": "cilium-cni",
		      "enable-debug": false,
		      "log-file": "/var/run/cilium/cilium-cni.log"
		    }
		  ]
		}
	`)
}

// heredoc strips the indentation a raw string literal picks up from being
// written inside a Go function.
//
// The same helper as cmd/kanea/units.go, and duplicated rather than shared for
// the reason that file is in package main: systemd tolerates leading
// whitespace in some places and not others, and a unit that is subtly wrong
// fails at `systemctl daemon-reload` rather than anywhere useful.
func heredoc(body string) string {
	lines := strings.Split(strings.Trim(body, "\n"), "\n")
	for i, line := range lines {
		lines[i] = strings.TrimLeft(line, "\t")
	}
	return strings.Join(lines, "\n") + "\n"
}

// Directories are the ones a running install needs that no artefact creates.
func (l Layout) Directories() []struct {
	Path string
	Mode os.FileMode
} {
	return []struct {
		Path string
		Mode os.FileMode
	}{
		{l.BinDir(), 0o755},
		{l.CNIBinDir(), 0o755},
		{filepath.Join(l.ConfDir, "containerd"), 0o755},
		{filepath.Join(l.ConfDir, "cni", "net.d"), 0o755},
		{filepath.Join(l.DataDir, "containerd"), 0o710},
		// 0700: etcd holds Cilium's identities and the kvstore is loopback-only.
		{filepath.Join(l.DataDir, "etcd"), 0o700},
		{l.RunDir, 0o710},
	}
}

// CreateDirectories makes them, with the modes they need.
func (l Layout) CreateDirectories() error {
	for _, d := range l.Directories() {
		if err := os.MkdirAll(d.Path, d.Mode); err != nil {
			return fmt.Errorf("create %s: %w", d.Path, err)
		}
		// MkdirAll honours umask, so the mode is set explicitly afterwards —
		// the same correction cmd/kanea/init.go makes for the data directory.
		if err := os.Chmod(d.Path, d.Mode); err != nil {
			return fmt.Errorf("chmod %s: %w", d.Path, err)
		}
	}
	return nil
}
