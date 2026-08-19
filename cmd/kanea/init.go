package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/backup"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/nodeconfig"
	"github.com/m18h/kanea/internal/provision"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/secrets"
	"golang.org/x/crypto/chacha20poly1305"
)

// runInit is `kanea init`: first-install checks, the key ceremony, and the
// systemd units (PRD §16.2, §15.3, §5.2.11).
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dataDir := fs.String("data-dir", defaultDataDir, "state directory")
	logDir := fs.String("log-dir", defaultLogDir, "workload log directory")
	unitDir := fs.String("unit-dir", defaultUnitDir, "where to write systemd units")
	networkMode := fs.String("network", networkEBPF, "network mode: ebpf or netns")
	containerdSocket := fs.String("containerd", runtime.DefaultSocket, "containerd socket")
	reserve := fs.String("reserve", defaultReserve,
		"memory reserved for the control plane (PRD §5.2.11)")
	skipChecks := fs.Bool("skip-checks", false, "run the ceremony without the preflight checks")
	skipUnits := fs.Bool("skip-units", false, "do not write systemd units")
	noInstall := fs.Bool("no-install", false,
		"do not install the host components (PRD §5.2.12); assume they are already there")
	bundlePath := fs.String("bundle", "", "install the host components from an offline bundle")
	prefix := fs.String("prefix", provision.DefaultPrefix, "where component binaries are installed")
	nodeCIDR := fs.String("node-cidr", provision.DefaultNodeCIDR,
		"this node's container subnet; also moves the internal DNS address, its .1")
	clusterCIDR := fs.String("cluster-cidr", provision.DefaultClusterCIDR,
		"what the datapath masquerades as internal; it must contain --node-cidr")
	nodeCIDR6 := fs.String("node-cidr6", "",
		"this node's IPv6 container subnet (PRD v1.41, opt-in); requires the other two *6 flags, ULA recommended")
	clusterCIDR6 := fs.String("cluster-cidr6", "",
		"the routed IPv6 range; must contain --node-cidr6")
	serviceCIDR6 := fs.String("service-cidr6", "",
		"IPv6 pool for service frontend twins")
	buildkitSocket := fs.String("buildkit", gitops.DefaultBuildkitSocket,
		"rootless buildkitd address (\"off\" skips the build daemon)")
	listenFlag := fs.String("listen", api.DefaultListenAddr,
		"API/dashboard network address written into the kanead unit (\"none\" keeps it socket-only)")
	listenCert := fs.String("listen-cert", "", "TLS certificate for --listen (required beyond loopback)")
	listenKey := fs.String("listen-key", "", "TLS private key for --listen")
	adminUser := fs.String("admin-user", "", "first admin's username (default: prompt)")
	noStart := fs.Bool("no-start", false,
		"write units but do not start kanead or create the first account")
	timeout := fs.Duration("timeout", 2*time.Minute, "how long to wait for kanead to come up")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Prompted only when not passed; detected here, so a script that sets the
	// flag (to anything, including the default) never consumes a stdin line.
	explicitListen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "listen" {
			explicitListen = true
		}
	})
	// Refused, not defaulted: before v1.36 any unknown value here silently
	// meant the product mode, so a typo configured a node by accident.
	if err := validNetworkMode(*networkMode); err != nil {
		return err
	}
	// The full six-flag validation kanead itself performs at startup, run
	// here first so the refusal lands in front of whoever typed the flags
	// rather than in the journal after the unit is written.
	if _, err := parseAgentCIDRs(*nodeCIDR, *clusterCIDR, reconciler.DefaultServiceCIDR,
		*nodeCIDR6, *clusterCIDR6, *serviceCIDR6); err != nil {
		return err
	}

	o := newOut()
	o.printf("kanea init: %s\n\n", version)

	// One reader for every prompt in this run. A second bufio.Reader over
	// os.Stdin would buffer ahead and swallow lines meant for a later prompt:
	// invisible on a terminal, fatal for a piped init.
	reader := bufio.NewReader(os.Stdin)

	// Settled first, before any check or install runs: a refused address
	// should cost the operator nothing but the retype.
	//
	// The §15.1 server config is consulted before the prompt (v1.61): a
	// bind.api_addr in kanea.hcl with no explicit --listen means the file owns
	// the listener; the question is not asked and no listen flags are
	// rendered into the unit, because a unit that repeated the file's answer
	// would turn the file off. An explicit --listen wins, as everywhere.
	nodeCfg, err := nodeconfig.Probe(nodeconfig.DefaultPath)
	if err != nil {
		return err
	}
	fileAddr, fileOwned, err := listenFromServerConfig(nodeCfg, explicitListen)
	if err != nil {
		return err
	}
	var listenAddr, unitListen, unitListenCert, unitListenKey string
	if fileOwned {
		listenAddr = fileAddr
		o.printf("API/dashboard listener: %s (from %s)\n\n", listenAddr, nodeCfg.Path)
	} else {
		if nodeCfg.Bind != nil && explicitListen {
			o.printf("Note: --listen wins; %s's bind stanza is not consulted.\n\n", nodeCfg.Path)
		}
		decision, err := resolveListen(o, reader, explicitListen, *listenFlag, *listenCert, *listenKey)
		if err != nil {
			return err
		}
		listenAddr = decision.addr
		unitListen = listenAddr
		unitListenCert, unitListenKey = decision.cert, decision.key
		if decision.provisionPair {
			// The default 10-year pair (v1.80): minted once and left alone on
			// re-runs. Provisioned here, before the checks and the install,
			// like the address itself, so a failed re-run still finds it there.
			if err := ensureAPIPair(o, decision.addr, provisionedAPICertPath, provisionedAPIKeyPath); err != nil {
				return err
			}
			unitListenCert, unitListenKey = provisionedAPICertPath, provisionedAPIKeyPath
			o.println()
		}
	}

	// `--containerd external` adopts the daemon already on the node instead of
	// installing one. Resolved here so the checks below and the install below
	// agree about which socket this node's runtime lives on.
	adoptContainerd := *containerdSocket == "external"
	effectiveSocket := *containerdSocket
	if adoptContainerd {
		effectiveSocket = provision.DistroContainerdSocket
	}

	layout := componentLayout(*prefix, *nodeCIDR, *clusterCIDR)
	layout.NodeCIDR6, layout.ClusterCIDR6 = *nodeCIDR6, *clusterCIDR6
	opts := preflightOptions{
		dataDir: *dataDir, containerdSocket: effectiveSocket,
		networkMode:    *networkMode,
		buildkitSocket: *buildkitSocket,
		layout:         layout,
		serviceCIDR:    reconciler.DefaultServiceCIDR,
		serviceCIDR6:   *serviceCIDR6,
	}

	// The platform checks gate, and only they do. They are the things no
	// installer can supply (a kernel, cgroups v2, a clock) so failing one
	// means this node cannot run Kanea however much software is placed on it.
	// The component checks come after the install, where they verify rather
	// than admit: running them first would fail every fresh node on the
	// absence of exactly the software the next step exists to install.
	if !*skipChecks {
		o.println("Checking this node:")
		if !renderChecks(o, platformChecks(opts)) {
			o.println()
			// Refused rather than warned about. An init that continues past a
			// failed check produces a node that looks configured and is not,
			// and the operator finds out at the first deploy.
			return errors.New("this node is not ready; fix the failures above " +
				"(or re-run with --skip-checks if you know better)")
		}
		o.println()
	}

	if !*noInstall {
		o.println("Installing the host components:")
		installArgs := []string{
			"--prefix", *prefix, "--unit-dir", *unitDir,
			"--node-cidr", *nodeCIDR, "--cluster-cidr", *clusterCIDR,
		}
		if *nodeCIDR6 != "" {
			installArgs = append(installArgs,
				"--node-cidr6", *nodeCIDR6, "--cluster-cidr6", *clusterCIDR6)
		}
		if *bundlePath != "" {
			installArgs = append(installArgs, "--bundle", *bundlePath)
		}
		if adoptContainerd {
			installArgs = append(installArgs, "--containerd", "external")
		}
		if err := runInstall(installArgs); err != nil {
			return err
		}
		o.println()
	}

	if err := createLayout(o, *dataDir, *logDir, provision.DefaultConfDir); err != nil {
		return err
	}
	// The CLI socket group (PRD v1.48, §13.1), created empty: membership is
	// root-equivalent and granted only by an operator's own usermod, so an
	// empty group changes nothing. kanead applies it to the socket at startup,
	// which is why it exists before the daemon is first enabled below. A
	// warning, not a failure: the CLI works over sudo either way.
	if err := provision.EnsureGroup(context.Background(), api.SocketGroup, nil); err != nil {
		o.printf("WARN  %v\n      (the CLI still works with sudo)\n", err)
	}
	// The edge's own account (PRD §5.2.6): the process split is only a
	// boundary if the edge is not root, and the certificate bundle's 0640
	// group-read half names this user's group. Same warning shape as the
	// socket group: an edge run by hand as root still works, it just is not
	// the boundary the threat model describes.
	if err := provision.EnsureUser(context.Background(), provision.EdgeUser, nil); err != nil {
		o.printf("WARN  %v\n      (the kanea-edge unit will not start until it exists)\n", err)
	}
	if err := keyCeremony(o, filepath.Join(*dataDir, secrets.KeyFileName), reader); err != nil {
		return err
	}
	if !*skipUnits {
		if err := writeUnits(o, unitOptions{
			dir: *unitDir, dataDir: *dataDir, logDir: *logDir,
			reserve: *reserve, binary: executablePath(),
			network: *networkMode, nodeCIDR: *nodeCIDR, clusterCIDR: *clusterCIDR,
			nodeCIDR6: *nodeCIDR6, clusterCIDR6: *clusterCIDR6, serviceCIDR6: *serviceCIDR6,
			listen: unitListen, listenCert: unitListenCert, listenKey: unitListenKey,
		}); err != nil {
			return err
		}
	}

	o.println()
	if *skipUnits || *noStart || !systemdAvailable() {
		// The pre-v1.45 ending, kept for the nodes it served: no systemd to
		// drive, or an operator who asked init to stop at the files.
		printManualNext(o)
		return o.Err()
	}
	if err := bootstrapDaemon(o, reader, bootstrapOptions{
		listen: listenAddr, adminUser: *adminUser, timeout: *timeout,
		network:  *networkMode,
		nodeCIDR: *nodeCIDR, clusterCIDR: *clusterCIDR, serviceCIDR: reconciler.DefaultServiceCIDR,
		nodeCIDR6: *nodeCIDR6, clusterCIDR6: *clusterCIDR6, serviceCIDR6: *serviceCIDR6,
		client: api.NewClient(api.DefaultSocket),
		run: func(ctx context.Context, args ...string) error {
			return systemctl(ctx, *timeout, args...)
		},
	}); err != nil {
		return err
	}
	return o.Err()
}

// defaultUnitDir is where systemd looks for locally-installed units.
const defaultUnitDir = "/etc/systemd/system"

// defaultReserve is the control plane's memory floor (PRD §5.2.11, v1.62).
// It covers a control plane that does not build: a node running pipelines
// raises --reserve, because buildkitd alone holds ~157 MiB resident.
const defaultReserve = "256M"

// createLayout makes the directories, with the modes they need.
func createLayout(o *out, dataDir, logDir, confDir string) error {
	// 0750 on the data directory: it holds the master key, the secrets bucket
	// and every certificate. 0750 on logs: workload output can carry anything a
	// workload printed. 0755 on the config directory: kanea.hcl is policy, not
	// a secret, and no example file is written; the default is that the
	// server config does not exist (PRD §15.1).
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{
		{dataDir, 0o750},
		{filepath.Join(dataDir, volumeSubdir), 0o750},
		{filepath.Join(dataDir, resolvSubdir), 0o755},
		{logDir, 0o750},
		{confDir, 0o755},
	} {
		if err := os.MkdirAll(dir.path, dir.mode); err != nil {
			return fmt.Errorf("create %s: %w", dir.path, err)
		}
		// MkdirAll honours umask, so the mode is set explicitly afterwards.
		if err := os.Chmod(dir.path, dir.mode); err != nil {
			return fmt.Errorf("chmod %s: %w", dir.path, err)
		}
	}
	o.printf("Created %s, %s and %s\n", dataDir, logDir, confDir)
	return nil
}

// keyCeremony generates and escrows the master key (PRD §15.3).
//
// The ceremony exists because of one asymmetry: losing this key costs every
// secret and every backup, and there is no recovery path at all, while the
// cost of writing it down is thirty seconds. Left to a warning in a log nobody
// reads, that trade gets made the wrong way, every time, and the consequence
// arrives months later during an incident.
//
// So the key is printed once and the operator has to type it back. Not a y/n
// prompt: the point is to prove they actually recorded it, and "press y to
// confirm you have done a thing" proves nothing.
//
// The reader is the caller's shared stdin reader: the ceremony must not wrap
// os.Stdin itself, because a private bufio.Reader buffers ahead and would
// swallow the lines a later prompt (the first admin's, v1.45) is waiting for.
func keyCeremony(o *out, path string, reader *bufio.Reader) error {
	if _, err := os.Stat(path); err == nil {
		// Never regenerated. A second key would leave every existing secret and
		// every existing archive unreadable, silently.
		o.printf("Master key already present at %s; leaving it alone.\n", path)
		o.println("  If you have not backed it up, do that now: without it every")
		o.println("  stored secret and every encrypted backup is unrecoverable.")
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("check %s: %w", path, err)
	}

	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generate the master key: %w", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	o.println()
	o.println("═══════════════════════════════════════════════════════════════════")
	o.println("  MASTER KEY: write this down now. It is shown once.")
	o.println()
	o.printf("      %s\n", encoded)
	o.println()
	o.println("  This key encrypts every secret in the store and every backup")
	o.println("  archive. If the node dies and you do not have this, the backups")
	o.println("  are unreadable. There is no recovery path, no escrow service and")
	o.println("  nothing Kanea can do about it.")
	o.println()
	o.println("  Put it in a password manager, a sealed envelope, or both.")
	o.println("═══════════════════════════════════════════════════════════════════")
	o.println()
	o.printf("Type the key back to confirm you have recorded it: ")
	if err := o.Err(); err != nil {
		return err
	}

	matched, err := confirm(reader, encoded)
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if !matched {
		// The key is discarded rather than written. An operator who could not
		// type it back does not have it, and writing it anyway would produce
		// exactly the situation this ceremony exists to prevent, with the
		// added insult of having asked.
		return errors.New("that does not match; nothing was written. " +
			"Re-run `kanea init` when you have somewhere to put the key")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("key directory: %w", err)
	}
	// O_EXCL: the check above is not a lock, and two inits racing must not each
	// think they wrote the key.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304; operator input
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := f.Write(key); err != nil {
		return errors.Join(fmt.Errorf("write %s: %w", path, err), f.Close())
	}
	// Synced before anything is encrypted under it: a key lost to a power cut
	// after the first secret was written makes that secret permanently
	// unreadable.
	if err := f.Sync(); err != nil {
		return errors.Join(fmt.Errorf("sync %s: %w", path, err), f.Close())
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}

	keys, err := backup.DeriveKeys(key)
	if err != nil {
		return err
	}
	o.println()
	o.printf("Master key written to %s (mode 0600).\n", path)
	o.printf("Its backup fingerprint is %s: every archive manifest carries this,\n", keys.ID)
	o.println("so you can tell which key an archive needs without decrypting it.")
	return nil
}

// executablePath is this binary's absolute path, for the unit files.
func executablePath() string {
	path, err := os.Executable()
	if err != nil {
		return "/usr/local/bin/kanea"
	}
	resolved, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return resolved
}

// componentLayout locates what `kanea install` placed, given a prefix.
//
// The other three directories are not configurable per command: a node whose
// components live in one prefix but whose configuration lives somewhere
// unrelated is a node nobody can support, and the flag exists for packaging
// rather than for taste.
func componentLayout(prefix string, cidrs ...string) provision.Layout {
	layout := provision.DefaultLayout()
	if prefix != "" {
		layout.Prefix = prefix
	}
	if len(cidrs) == 2 {
		layout.NodeCIDR, layout.ClusterCIDR = cidrs[0], cidrs[1]
	}
	return layout
}

// runDoctor is `kanea doctor`: the preflight checks on their own.
func runDoctor(args []string) error {
	fset := flag.NewFlagSet("doctor", flag.ContinueOnError)
	dataDir := fset.String("data-dir", defaultDataDir, "state directory")
	networkMode := fset.String("network", networkEBPF, "network mode: ebpf or netns")
	containerdSocket := fset.String("containerd", runtime.DefaultSocket, "containerd socket")
	buildkitSocket := fset.String("buildkit", gitops.DefaultBuildkitSocket, "buildkitd address")
	prefix := fset.String("prefix", provision.DefaultPrefix, "component install prefix")
	// Exactly one check reaches the network; whether component artefacts are
	// fetchable, which is what tells an operator if an upgrade needs a bundle
	// carried in. On an air-gapped node the answer is known and the probe is
	// just a five-second wait, and a `doctor` that pauses on every run is a
	// `doctor` that stops being run.
	offline := fset.Bool("offline", false, "skip the upstream reachability probe (air-gapped nodes)")
	// The two halves of the overlap check. They live on different commands in
	// real life (one at install, one on kanead) so doctor has to be told
	// both to notice a collision neither side can see alone.
	docNodeCIDR := fset.String("node-cidr", provision.DefaultNodeCIDR, "this node's container subnet")
	docClusterCIDR := fset.String("cluster-cidr", provision.DefaultClusterCIDR, "the native routing CIDR")
	docServiceCIDR := fset.String("service-cidr", reconciler.DefaultServiceCIDR,
		"kanead's service frontend pool, checked for overlap with the container subnet")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if err := validNetworkMode(*networkMode); err != nil {
		return err
	}

	o := newOut()
	o.printf("kanea doctor: %s\n\n", version)
	ok := renderChecks(o, preflight(preflightOptions{
		dataDir: *dataDir, containerdSocket: *containerdSocket,
		networkMode:    *networkMode,
		buildkitSocket: *buildkitSocket,
		layout:         componentLayout(*prefix, *docNodeCIDR, *docClusterCIDR),
		serviceCIDR:    *docServiceCIDR,
		offline:        *offline,
	}))
	if err := o.Err(); err != nil {
		return err
	}
	if !ok {
		return errors.New("this node has problems that will stop kanead working")
	}
	return nil
}
