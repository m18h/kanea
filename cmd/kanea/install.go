package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/m18h/kanea/internal/provision"
)

// `kanea install` — place the pinned host components (PRD §5.2.12).
//
// Separate from `kanea init` because it is re-runnable and inspectable, and
// because upgrading a component on a node that has been running for a year is
// not a first install. `init` calls the same code.

// runInstall is `kanea install`.
func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	only := fs.String("only", "", "comma-separated components (default: all)")
	bundlePath := fs.String("bundle", "", "install from an offline bundle instead of upstream")
	dryRun := fs.Bool("dry-run", false, "resolve and verify every artefact, write nothing")
	force := fs.Bool("force", false, "reinstall components already at the pinned version")
	prefix := fs.String("prefix", provision.DefaultPrefix, "where component binaries are installed")
	confDir := fs.String("conf-dir", provision.DefaultConfDir, "component configuration directory")
	dataDir := fs.String("data-dir", provision.DefaultDataDir, "component state directory")
	runDir := fs.String("run-dir", provision.DefaultRunDir, "component socket directory")
	unitDir := fs.String("unit-dir", defaultUnitDir, "where to write systemd units")
	skipUnits := fs.Bool("skip-units", false, "install binaries without writing systemd units")
	listOnly := fs.Bool("list", false, "print the pinned component versions and exit")
	adopt := fs.String("containerd", "",
		"\"external\" (or a socket path) adopts an existing containerd instead of installing one")
	nodeCIDR := fs.String("node-cidr", provision.DefaultNodeCIDR,
		"this node's container subnet; its .1 is the datapath host address")
	clusterCIDR := fs.String("cluster-cidr", provision.DefaultClusterCIDR,
		"the native routing CIDR; it must contain --node-cidr")
	arch := fs.String("arch", provision.HostArch(),
		"target architecture; only meaningful with --dry-run, to verify another arch's artefacts")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// A cross-architecture install would place binaries this kernel cannot
	// execute, and the failure would arrive at the first `systemctl start`
	// rather than here. Verification is the one thing that is architecture-
	// independent, so that is the one thing the flag is allowed to change.
	if *arch != provision.HostArch() && !*dryRun {
		return fmt.Errorf("--arch %s only applies to --dry-run: installing %s binaries on a %s node "+
			"would produce a node whose daemons cannot start", *arch, *arch, provision.HostArch())
	}

	manifest, err := provision.Load()
	if err != nil {
		return err
	}
	o := newOut()

	if *listOnly {
		return listComponents(o, manifest)
	}

	components := manifest.All()
	if *only != "" {
		components, err = manifest.Select(strings.Split(*only, ","))
		if err != nil {
			return err
		}
		if len(components) == 0 {
			return errors.New("--only matched no components")
		}
	}

	// Adopting an existing containerd: Kanea installs none, and the socket it
	// drives is the adopted one. This is the only configuration in which Kanea
	// depends on a containerd whose version it did not choose, which is why it
	// has to be asked for rather than inferred from one being present.
	adoptedSocket := ""
	if *adopt != "" {
		adoptedSocket = *adopt
		if adoptedSocket == "external" {
			adoptedSocket = provision.DistroContainerdSocket
		}
		components = withoutComponent(components, "containerd")
	}

	source, err := installSource(*bundlePath)
	if err != nil {
		return err
	}

	layout := provision.Layout{
		Prefix: *prefix, ConfDir: *confDir, DataDir: *dataDir,
		RunDir: *runDir, UnitDir: *unitDir,
		NodeCIDR: *nodeCIDR, ClusterCIDR: *clusterCIDR,
	}
	// Refused here rather than left to configure the datapath: a bad CIDR would
	// otherwise surface on a live node as unroutable alloc addresses rather than
	// as the plain "you wrote 10.244.0/24" it is.
	if err := layout.ValidateNetworking(); err != nil {
		return err
	}
	if adoptedSocket != "" {
		layout.ContainerdSocket = adoptedSocket
	}

	// Ctrl-C during a download should stop it, not leave a partial file the
	// next run treats as installed. Stage writes to a temporary path and only
	// renames after verification, so cancellation is safe by construction —
	// this just makes it prompt.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	o.printf("kanea install — %s\n\n", version)
	o.printf("Source: %s\n", source.Describe())
	o.printf("Prefix: %s\n\n", layout.Prefix)

	if !*dryRun {
		if err := layout.CreateDirectories(); err != nil {
			return err
		}
	}

	installer := &provision.Installer{
		Source: source,
		Layout: layout,
		Arch:   *arch,
		DryRun: *dryRun,
		Force:  *force,
	}

	// Phase one: the artefact components. containerd is among them, and
	// nothing can pull an image until it is running — the install bootstraps
	// itself in one direction (§5.2.12).
	artefacts, imageComponents := splitByKind(components)

	results, installErr := installer.Install(ctx, artefacts)
	renderInstallResults(o, results)
	if installErr != nil {
		if err := o.Err(); err != nil {
			return err
		}
		return installErr
	}

	if *dryRun {
		// Image components are pinned by digest, so there is nothing a dry run
		// could check that the manifest has not already fixed — and confirming
		// it would need a containerd this machine may not have.
		for _, c := range imageComponents {
			o.printf("  %s\t%s\t%s\n", provision.ActionPlanned, c.Display(), c.Summary)
		}
		o.println()
		o.println("Dry run: every artefact resolved and matched its pinned hash. Nothing was written.")
		return o.Err()
	}

	if !*skipUnits {
		if err := writeComponentFiles(o, layout, artefacts); err != nil {
			return err
		}
		if adoptedSocket != "" {
			dropIn := provision.AdoptedContainerdDropIn(layout.UnitDir)
			if err := provision.WriteFiles([]provision.ConfigFile{dropIn}); err != nil {
				return err
			}
			o.printf("Wrote %s\n", dropIn.Path)
			o.printf("Adopted the containerd at %s; none was installed.\n", adoptedSocket)
		}
	}

	// The FUSE stack (§8). Not a component — there is nothing to download,
	// only host state internal/storage has always assumed and nothing has ever
	// created. A failure here is reported rather than fatal: a node that never
	// mounts an S3 volume should not fail its install over it.
	if err := provision.SetupFUSE(ctx, nil); err != nil {
		o.printf("\nWARN  the FUSE stack could not be set up: %v\n", err)
		o.println("      S3 volumes will fail to mount until it is (PRD §8).")
	}

	// Phase two: bring containerd up, then pull the images through it.
	if len(imageComponents) > 0 {
		if err := installImages(ctx, o, installer, layout, imageComponents, artefacts, *skipUnits, bundleOf(source)); err != nil {
			return err
		}
	}

	o.println()
	o.println("Next:")
	if provision.SystemdAvailable() && !*skipUnits {
		o.println("  kanea doctor                    # confirm every component answers")
		o.println("  kanea init                      # key ceremony, accounts, kanead's own units")
	} else {
		o.println("  systemctl daemon-reload")
		o.printf("  systemctl enable --now %s\n", strings.Join(unitNames(components), " "))
		o.println("  kanea doctor")
	}
	return o.Err()
}

// splitByKind separates artefact components from image ones, preserving order.
func splitByKind(components []*provision.Component) (artefacts, imgs []*provision.Component) {
	for _, c := range components {
		if c.Kind == provision.KindImage {
			imgs = append(imgs, c)
			continue
		}
		artefacts = append(artefacts, c)
	}
	return artefacts, imgs
}

// bundleOf returns the bundle behind a Source, if it is one. Image components
// come out of a bundle as OCI archives rather than registry pulls.
func bundleOf(src provision.Source) *provision.BundleSource {
	b, _ := src.(*provision.BundleSource)
	return b
}

func writeComponentFiles(o *out, layout provision.Layout, components []*provision.Component) error {
	files := layout.Files(components, executablePath(), defaultReserve)
	if len(files) == 0 {
		return nil
	}
	if err := provision.WriteFiles(files); err != nil {
		return err
	}
	o.println()
	for _, f := range files {
		o.printf("Wrote %s\n", f.Path)
	}
	return nil
}

// installImages starts containerd and pulls the image components through it.
//
// Starting containerd here rather than leaving it to the operator is the point
// of the whole change: "install a runtime, then go and start it yourself, then
// come back and run this again" is the prerequisite list under a different
// name.
func installImages(ctx context.Context, o *out, installer *provision.Installer,
	layout provision.Layout, imageComponents, artefacts []*provision.Component,
	skipUnits bool, bundle *provision.BundleSource) error {

	if !provision.SystemdAvailable() {
		o.println()
		o.println("systemd is not running here, so containerd was installed but not started.")
		o.println("Start it and re-run `kanea install` to place the image components:")
		for _, c := range imageComponents {
			o.printf("  - %s (%s)\n", c.Name, c.Summary)
		}
		return nil
	}
	if skipUnits {
		o.println()
		o.println("--skip-units: containerd was not started, so the image components were left out.")
		return nil
	}

	systemd := provision.Systemd{}
	o.println()
	o.println("Starting containerd to pull the image components…")
	if err := systemd.DaemonReload(ctx); err != nil {
		return err
	}
	if err := systemd.EnableNow(ctx, requiredUnits(artefacts)...); err != nil {
		return err
	}
	if err := provision.WaitForSocket(ctx, layout.SocketPath(), containerdStartTimeout); err != nil {
		return fmt.Errorf("containerd did not come up: %w "+
			"(journalctl -u kanea-containerd)", err)
	}

	imageClient, err := provision.NewImageClient(layout.SocketPath(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = imageClient.Close() }() //nolint:errcheck // cleanup path

	// A bundle carries images as OCI archives. Loading them first means the
	// pull below finds them locally and never reaches for a registry — which
	// is the property that has to hold, not merely be likely.
	if bundle != nil {
		for _, c := range imageComponents {
			path, ok := bundle.ImageArchive(c)
			if !ok {
				return fmt.Errorf("%s is not in %s", c.Display(), bundle.Describe())
			}
			if err := imageClient.Import(ctx, path); err != nil {
				return err
			}
		}
	}

	installer.Images = imageClient
	results, err := installer.Install(ctx, imageComponents)
	renderInstallResults(o, results)
	if err != nil {
		return err
	}

	// The rootless build ceremony has to happen before the unit starts: the
	// unit runs as kanea-buildkit, and systemd's failure for a User= that does
	// not exist arrives as a start job failure with no explanation of why.
	if hasComponent(imageComponents, "buildkit") {
		if err := provision.SetupBuildkit(ctx, layout, nil); err != nil {
			return err
		}
	}

	if err := writeComponentFiles(o, layout, imageComponents); err != nil {
		return err
	}
	if err := systemd.DaemonReload(ctx); err != nil {
		return err
	}
	return systemd.EnableNow(ctx, requiredUnits(imageComponents)...)
}

// withoutComponent drops one by name, preserving install order.
func withoutComponent(components []*provision.Component, name string) []*provision.Component {
	out := make([]*provision.Component, 0, len(components))
	for _, c := range components {
		if c.Name != name {
			out = append(out, c)
		}
	}
	return out
}

func hasComponent(components []*provision.Component, name string) bool {
	for _, c := range components {
		if c.Name == name {
			return true
		}
	}
	return false
}

// containerdStartTimeout bounds the wait for containerd's socket.
const containerdStartTimeout = 60 * time.Second

// requiredUnits maps components to the units that must be running.
func requiredUnits(components []*provision.Component) []string {
	var out []string
	for _, name := range unitNames(components) {
		out = append(out, name+".service")
	}
	return out
}

// installSource picks where artefacts come from.
//
// A bundle turns network fetching off entirely rather than becoming a
// preference. An air-gapped install that silently reaches upstream for one
// missing component fails later, on a node nobody can reach — which is worse
// than failing here, where somebody is watching.
func installSource(bundlePath string) (provision.Source, error) {
	if bundlePath == "" {
		return provision.NewHTTPSource(), nil
	}
	return provision.OpenBundle(bundlePath)
}

// unitNames is what to enable after an install.
func unitNames(components []*provision.Component) []string {
	units := map[string]string{
		"containerd": "kanea-containerd",
		"buildkit":   "kanea-buildkit",
	}
	var out []string
	for _, c := range components {
		if u, ok := units[c.Name]; ok {
			out = append(out, u)
		}
	}
	return out
}

func renderInstallResults(o *out, results []provision.Result) {
	if len(results) == 0 {
		return
	}
	o.table()
	for _, r := range results {
		switch {
		case r.Err != nil:
			o.printf("  FAIL\t%s\t%s\n", r.Component.Display(), r.Err)
		case r.Reason != "":
			o.printf("  %s\t%s\t%s\n", r.Action, r.Component.Display(), r.Reason)
		default:
			o.printf("  %s\t%s\t%s\n", r.Action, r.Component.Display(), r.Component.Summary)
		}
	}
}

// listComponents prints the version matrix (PRD §15.4). It is the manifest, so
// there is one place to look and nothing to keep in step with it.
func listComponents(o *out, m *provision.Manifest) error {
	o.printf("Pinned host components — kanea %s\n\n", version)
	o.table()
	o.println("  COMPONENT\tVERSION\tKIND\tPIN")
	for _, c := range m.All() {
		pin := c.Digest
		if c.Kind != provision.KindImage {
			h, err := c.Hash(provision.HostArch())
			if err != nil {
				// A host arch Kanea does not publish for — a developer laptop.
				// The versions are still worth printing.
				h = "(not published for " + provision.HostArch() + ")"
			} else {
				h = "sha256:" + h[:12] + "…"
			}
			pin = h
		} else {
			pin = pin[:len("sha256:")+12] + "…"
		}
		o.printf("  %s\t%s\t%s\t%s\n", c.Name, c.Version, c.Kind, pin)
	}
	if err := o.Err(); err != nil {
		return err
	}
	_, err := fmt.Fprintln(os.Stdout,
		"\nThese are compiled into this binary. Changing one is a code change, not a flag.")
	return err
}
