package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zclconf/go-cty/cty"

	"github.com/m18h/kanea/internal/nodeconfig"
)

// Node configuration used to arrive as flags on the two daemons' ExecStart
// lines (PRD v1.115 retired them). This file converts an installed node: it
// reads the systemd units an older `kanea init` wrote, folds every flag into
// /etc/kanea/kanea.hcl with the precedence the node was running under (the
// flag beat the file), and rewrites the units to the flagless form.

const (
	kaneadUnit = "kanead.service"
	edgeUnit   = "kanea-edge.service"

	// migratedSuffix is appended to a drop-in whose ExecStart the migration
	// retired; systemd reads only *.conf, so the rename takes it out of play
	// while leaving it for the operator to inspect.
	migratedSuffix = ".migrated"

	// preMigrateSuffix names the copy of the operator's kanea.hcl taken
	// before the first rewrite.
	preMigrateSuffix = ".pre-migrate"

	migrateTimeout = 2 * time.Minute
)

// flagKind is how a legacy flag's value was typed, which is how its attribute
// is written.
type flagKind int

const (
	kindString flagKind = iota
	kindBool
	kindInt
	kindDuration
	// kindList was a comma-separated string flag; it is written as an HCL
	// list.
	kindList
)

// legacyFlag is one flag a daemon accepted before v1.115. path is the
// kanea.hcl attribute it became (nodeconfig.Editor's addressing); nil marks
// a flag migrateNode handles by hand.
type legacyFlag struct {
	name string
	kind flagKind
	path []string
}

// legacyAgentFlags is every flag `kanea agent` took, frozen: the flags are
// gone from the daemon, so this table is the only record of them and must
// never follow a later schema change by accident. In the order the flags
// were declared, which is the order their attributes are written in.
var legacyAgentFlags = []legacyFlag{
	{"data-dir", kindString, []string{"data_dir"}},
	{"backup-dir", kindString, []string{"backup", "dir"}},
	{"backup-s3", kindString, []string{"backup", "s3", "url"}},
	{"backup-s3-endpoint", kindString, []string{"backup", "s3", "endpoint"}},
	{"backup-s3-region", kindString, []string{"backup", "s3", "region"}},
	{"backup-s3-access-key", kindString, []string{"backup", "s3", "access_key"}},
	{"backup-s3-secret-key", kindString, []string{"backup", "s3", "secret_key"}},
	{"backup-s3-path-style", kindBool, []string{"backup", "s3", "path_style"}},
	{"backup-interval", kindDuration, []string{"backup", "snapshot_interval"}},
	{"backup-segment-interval", kindDuration, []string{"backup", "segment_interval"}},
	{"backup-retention", kindInt, []string{"backup", "retention"}},
	{"restore-if-empty", kindBool, []string{"backup", "restore_if_empty"}},
	{"log-dir", kindString, []string{"alloc_log_dir"}},
	{"volume-dir", kindString, []string{"storage", "volume_dir"}},
	{"socket", kindString, []string{"bind", "api_socket"}},
	{"containerd", kindString, []string{"containerd", "socket"}},
	{"network", kindString, nil},
	{"bpf-dir", kindString, []string{"network", "bpf_dir"}},
	{"node-cidr", kindString, []string{"network", "node_cidr"}},
	{"cluster-cidr", kindString, []string{"network", "cluster_cidr"}},
	{"node-cidr6", kindString, []string{"network", "node_cidr6"}},
	{"cluster-cidr6", kindString, []string{"network", "cluster_cidr6"}},
	{"service-cidr6", kindString, []string{"network", "service_cidr6"}},
	{"config", kindString, nil},
	{"allowed-host-paths", kindList, nil},
	{"passthrough-config", kindString, nil},
	{"secrets-providers-config", kindString, nil},
	{"secrets-sync-interval", kindDuration, []string{"secrets", "sync_interval"}},
	{"service-cidr", kindString, []string{"network", "service_cidr"}},
	{"dns-listen", kindString, []string{"dns", "listen"}},
	{"dns-upstream", kindList, []string{"dns", "upstreams"}},
	{"image-pull-policy", kindString, []string{"images", "pull_policy"}},
	{"image-gc", kindString, nil},
	{"base-domain", kindString, []string{"base_domain"}},
	{"edge-routes", kindString, []string{"edge", "routes_file"}},
	{"edge-certs", kindString, []string{"edge", "certs_file"}},
	{"edge-group", kindString, []string{"edge", "certs_group"}},
	{"tls-default", kindString, []string{"tls", "default_mode"}},
	{"tls-ca-name", kindString, []string{"tls", "ca_name"}},
	{"tls-certs-config", kindString, nil},
	{"publish-ports", kindString, []string{"edge", "publish", "ports"}},
	{"acme-email", kindString, []string{"acme", "email"}},
	{"acme-directory", kindString, []string{"acme", "directory"}},
	{"acme-ca-bundle", kindString, []string{"acme", "ca_bundle_file"}},
	{"acme-verify-url", kindString, []string{"acme", "verify_url"}},
	{"acme-dns-server", kindString, []string{"acme", "dns01", "server"}},
	{"acme-dns-zone", kindString, []string{"acme", "dns01", "zone"}},
	{"acme-dns-tsig-key", kindString, []string{"acme", "dns01", "tsig_key"}},
	{"acme-dns-tsig-secret", kindString, []string{"acme", "dns01", "tsig_secret"}},
	{"acme-dns-tsig-algorithm", kindString, []string{"acme", "dns01", "tsig_algorithm"}},
	{"dashboard", kindBool, []string{"dashboard", "enabled"}},
	{"dashboard-origins", kindList, []string{"dashboard", "origins"}},
	{"listen", kindString, nil},
	{"listen-cert", kindString, nil},
	{"listen-key", kindString, nil},
	{"insecure-cookies", kindBool, []string{"auth", "insecure_cookies"}},
	{"audit-retention", kindDuration, []string{"audit", "retention"}},
	{"oidc-issuer", kindString, []string{"auth", "oidc", "issuer"}},
	{"oidc-client-id", kindString, []string{"auth", "oidc", "client_id"}},
	{"oidc-client-secret", kindString, []string{"auth", "oidc", "client_secret"}},
	{"oidc-redirect-url", kindString, []string{"auth", "oidc", "redirect_url"}},
	{"oidc-scopes", kindList, []string{"auth", "oidc", "scopes"}},
	{"oidc-role-claim", kindString, []string{"auth", "oidc", "role_claim"}},
	{"oidc-admin-claims", kindList, []string{"auth", "oidc", "admin_claims"}},
	{"oidc-viewer-claims", kindList, []string{"auth", "oidc", "viewer_claims"}},
	{"ldap-url", kindString, []string{"auth", "ldap", "url"}},
	{"ldap-bind-dn", kindString, []string{"auth", "ldap", "bind_dn"}},
	{"ldap-bind-password", kindString, []string{"auth", "ldap", "bind_password"}},
	{"ldap-user-base-dn", kindString, []string{"auth", "ldap", "user_base_dn"}},
	{"ldap-user-filter", kindString, []string{"auth", "ldap", "user_filter"}},
	{"ldap-group-base-dn", kindString, []string{"auth", "ldap", "group_base_dn"}},
	{"ldap-group-filter", kindString, []string{"auth", "ldap", "group_filter"}},
	{"ldap-admin-groups", kindList, []string{"auth", "ldap", "admin_groups"}},
	{"ldap-viewer-groups", kindList, []string{"auth", "ldap", "viewer_groups"}},
	{"ldap-ca", kindString, []string{"auth", "ldap", "ca_file"}},
	{"metrics-interval", kindDuration, []string{"metrics", "interval"}},
	{"containerd-metrics", kindString, []string{"metrics", "containerd_url"}},
	{"edge-metrics", kindString, []string{"metrics", "edge_url"}},
	{"autoscale", kindBool, []string{"scaling", "enabled"}},
	{"buildkit", kindString, []string{"builds", "buildkit_addr"}},
	{"build-log-dir", kindString, []string{"builds", "log_dir"}},
	{"sync-interval", kindDuration, []string{"gitops", "sync_interval"}},
	{"notify-allow-private", kindBool, []string{"notifications", "allow_private"}},
	{"notify-allow-http", kindBool, []string{"notifications", "allow_http"}},
	{"event-retention", kindInt, []string{"notifications", "event_retention"}},
	{"insecure-registry", kindBool, []string{"builds", "insecure_registry"}},
	{"registry", kindString, []string{"builds", "registry_addr"}},
	{"log-level", kindString, []string{"log_level"}},
}

// legacyEdgeFlags is every flag `kanea edge` took, frozen like the agent's.
var legacyEdgeFlags = []legacyFlag{
	{"routes", kindString, []string{"edge", "routes_file"}},
	{"http", kindString, []string{"bind", "edge_http"}},
	{"https", kindString, []string{"bind", "edge_https"}},
	{"certs", kindString, []string{"edge", "certs_file"}},
	{"status", kindString, []string{"edge", "status_addr"}},
	{"poll", kindDuration, []string{"edge", "poll_interval"}},
	{"drain", kindDuration, []string{"edge", "drain_timeout"}},
	{"publish-drain", kindDuration, []string{"edge", "publish", "drain_timeout"}},
	{"max-published-conns", kindInt, []string{"edge", "publish", "max_conns"}},
	{"functions-port", kindInt, []string{"edge", "functions_port"}},
	{"body-timeout", kindDuration, []string{"edge", "body_timeout"}},
	{"upstream-timeout", kindDuration, []string{"edge", "upstream_timeout"}},
	{"security-headers", kindBool, []string{"edge", "security_headers"}},
	{"rate-limit-buckets", kindInt, []string{"edge", "rate_limit_buckets"}},
	{"memory-limit", kindString, []string{"edge", "memory_limit"}},
	{"log-level", kindString, []string{"edge", "log_level"}},
}

// bindAPIAttrs is the API half of the bind stanza: what --listen replaced as
// a whole, never attribute by attribute.
var bindAPIAttrs = []string{"api_addr", "api_tls", "api_domain", "api_cert", "api_key"}

type migrateOptions struct {
	unitDir  string // where kanead.service and kanea-edge.service live
	confPath string // the node config to write
	dryRun   bool
}

// migrateReport is what a migration did, or with dryRun would do.
type migrateReport struct {
	// migrated is false when there was nothing to convert; every other
	// field is then empty apart from notes.
	migrated bool
	confPath string
	// config is the resulting node config, whether or not it was written.
	config []byte
	// agentExecStart and edgeExecStart are the units' new ExecStart lines;
	// edgeExecStart is empty on a node with no kanea-edge.service.
	agentExecStart string
	edgeExecStart  string
	// renamedDropIns are the drop-ins that carried an ExecStart, by their
	// original path; each is now beside itself with migratedSuffix.
	renamedDropIns []string
	// sideFiles are the files flags named whose content now lives in the
	// node config. They are left on disk and no longer read.
	sideFiles []string
	// backup is where the previous node config was copied, when it was.
	backup string
	notes  []string
}

// Seams for the tests: the paths a self-migrating daemon uses, and how it
// reaches systemd.
var (
	migrateDefaults  = migrateOptions{unitDir: defaultUnitDir, confPath: nodeconfig.DefaultPath}
	migrateSystemctl = systemctl
)

// errDaemonMigrated is how a kanead that has just rewritten its own unit
// exits: non-zero, so Restart=always starts it again under the new one.
var errDaemonMigrated = errors.New("node configuration migrated to " + nodeconfig.DefaultPath +
	"; restarting under the rewritten unit")

func runConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: kanea config migrate [flags]")
	}
	switch args[0] {
	case "migrate":
		return runConfigMigrate(args[1:])
	default:
		return fmt.Errorf("unknown config command %q (have: migrate)", args[0])
	}
}

func runConfigMigrate(args []string) error {
	fset := flag.NewFlagSet("config migrate", flag.ContinueOnError)
	unitDir := fset.String("unit-dir", migrateDefaults.unitDir, "where the systemd units live")
	dryRun := fset.Bool("dry-run", false, "print the resulting node config and unit lines; write nothing")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() > 0 {
		return fmt.Errorf("kanea config migrate takes no arguments (got %q)", fset.Arg(0))
	}
	opts := migrateOptions{unitDir: *unitDir, confPath: migrateDefaults.confPath, dryRun: *dryRun}
	report, err := migrateNode(opts)
	if err != nil {
		return err
	}
	o := newOut()
	printMigrateReport(o, report, opts.dryRun)
	if err := o.Err(); err != nil {
		return err
	}
	if !report.migrated || opts.dryRun || !systemdAvailable() {
		return nil
	}
	ctx := context.Background()
	if err := migrateSystemctl(ctx, migrateTimeout, "daemon-reload"); err != nil {
		return err
	}
	// reset-failed fails for a unit that is not failed or not loaded, which
	// is the common case here; it only matters when the edge has already hit
	// its start limit.
	_ = migrateSystemctl(ctx, migrateTimeout, "reset-failed", "kanea-edge", "kanead") //nolint:errcheck // see above: failing is the common case
	if err := migrateSystemctl(ctx, migrateTimeout, "restart", "kanea-edge"); err != nil {
		return err
	}
	return migrateSystemctl(ctx, migrateTimeout, "restart", "kanead")
}

func printMigrateReport(o *out, r migrateReport, dryRun bool) {
	if !r.migrated {
		o.println("Nothing to migrate.")
		for _, note := range r.notes {
			o.println(note)
		}
		return
	}
	if dryRun {
		o.printf("Would write %s:\n\n%s\n", r.confPath, r.config)
		o.println("Would set in " + kaneadUnit + ":")
		o.println("  " + r.agentExecStart)
		if r.edgeExecStart != "" {
			o.println("Would set in " + edgeUnit + ":")
			o.println("  " + r.edgeExecStart)
		}
		for _, path := range r.renamedDropIns {
			o.printf("Would rename %s to %s (its other directives go with it)\n", path, path+migratedSuffix)
		}
	} else {
		if r.backup != "" {
			o.printf("Kept the previous node config as %s\n", r.backup)
		}
		o.printf("Wrote %s\n", r.confPath)
		o.printf("%s: %s\n", kaneadUnit, r.agentExecStart)
		if r.edgeExecStart != "" {
			o.printf("%s: %s\n", edgeUnit, r.edgeExecStart)
		}
		for _, path := range r.renamedDropIns {
			o.printf("Renamed %s to %s (its other directives went with it)\n", path, path+migratedSuffix)
		}
	}
	for _, path := range r.sideFiles {
		o.printf("%s is folded into %s and no longer read\n", path, r.confPath)
	}
	for _, note := range r.notes {
		o.println(note)
	}
}

// daemonArgs answers a daemon that was handed arguments. Neither takes any;
// the one thing an argument can still mean is an older unit's flags, which
// kanead converts once and then exits to be restarted without them.
func daemonArgs(name string, args []string) error {
	for _, arg := range args {
		if arg == "-h" || arg == "-help" || arg == "--help" {
			fmt.Fprintf(os.Stderr, "usage: kanea %s\n\ntakes no flags; its configuration is %s\n",
				name, nodeconfig.DefaultPath)
			return flag.ErrHelp
		}
	}
	refusal := fmt.Errorf("kanea %s takes no arguments: node configuration lives in %s. "+
		"To convert an older unit's flags: sudo kanea config migrate", name, nodeconfig.DefaultPath)
	// Only kanead migrates, and only when systemd started it: the edge is
	// not root, and a person typing flags should be told, not have their
	// units rewritten.
	if name != "agent" || os.Getenv("INVOCATION_ID") == "" {
		return refusal
	}
	report, err := migrateNode(migrateDefaults)
	if err != nil {
		return fmt.Errorf("converting this unit's flags into %s (fix the cause, then run: sudo kanea config migrate): %w",
			nodeconfig.DefaultPath, err)
	}
	// Nothing to migrate, yet here are arguments: refusing is what stops
	// this from becoming a silent restart loop.
	if !report.migrated {
		return refusal
	}
	ctx := context.Background()
	if err := migrateSystemctl(ctx, migrateTimeout, "daemon-reload"); err != nil {
		fmt.Fprintf(os.Stderr, "kanea agent: %v\n", err)
	}
	// The edge has been failing on its own flags every two seconds and may
	// have hit systemd's start limit; without this the restart is refused.
	_ = migrateSystemctl(ctx, migrateTimeout, "reset-failed", "kanea-edge") //nolint:errcheck // fails when the edge is not in the failed state, which is fine
	if err := migrateSystemctl(ctx, migrateTimeout, "restart", "kanea-edge"); err != nil {
		fmt.Fprintf(os.Stderr, "kanea agent: %v\n", err)
	}
	return errDaemonMigrated
}

// migrateNode converts the units in opts.unitDir. It calls no systemd and
// writes nothing until everything has been read, parsed and validated; the
// node config is written before the units, so an interruption between the
// two leaves flags that convert to the same file on the next run.
func migrateNode(opts migrateOptions) (migrateReport, error) {
	report := migrateReport{confPath: opts.confPath}

	agent, err := readUnit(opts.unitDir, kaneadUnit)
	if errors.Is(err, fs.ErrNotExist) {
		return report, fmt.Errorf("no %s in %s: nothing to migrate", kaneadUnit, opts.unitDir)
	}
	if err != nil {
		return report, err
	}
	edgeU, err := readUnit(opts.unitDir, edgeUnit)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return report, err
	}

	agentBin, agentArgs, err := agent.legacyArgs("agent")
	if err != nil {
		return report, err
	}
	var edgeBin string
	var edgeArgs []string
	if edgeU != nil {
		if edgeBin, edgeArgs, err = edgeU.legacyArgs("edge"); err != nil {
			return report, err
		}
	}
	repo := agent.env["KANEA_REPO"]
	requireSig := agent.env["KANEA_REQUIRE_SIGNATURE"] == "1"
	hasFlags := len(agentArgs)+len(edgeArgs) > 0
	if !hasFlags && repo == "" && !requireSig {
		report.notes = append(report.notes, "Neither unit carries flags.")
		return report, nil
	}

	agentSet, err := parseLegacyFlags(kaneadUnit, legacyAgentFlags, agentArgs)
	if err != nil {
		return report, err
	}
	edgeSet, err := parseLegacyFlags(edgeUnit, legacyEdgeFlags, edgeArgs)
	if err != nil {
		return report, err
	}
	// The network mode is not a setting any more (PRD v1.115): a Linux node
	// runs the eBPF datapath. "ebpf", which every unit `kanea init` wrote
	// carries, converts to nothing. "netns" is refused rather than converted:
	// its allocs have bare namespaces, and dropping the flag would put them
	// on a datapath they were never attached to without anyone having asked
	// for that.
	if mode, set := agentSet["network"].(string); set && mode != "ebpf" {
		return report, fmt.Errorf("%s has --network %s, and the network mode is no longer a setting: "+
			"a Linux node runs the eBPF datapath. That mode enforced no policy and balanced no service. "+
			"Remove the flag from the unit to move this node onto the datapath, then run the migration again",
			kaneadUnit, mode)
	}
	for _, pair := range [][2]string{{"edge-routes", "routes"}, {"edge-certs", "certs"}} {
		a, aSet := agentSet[pair[0]].(string)
		e, eSet := edgeSet[pair[1]].(string)
		if aSet && eSet && a != e {
			return report, fmt.Errorf("%s has --%s %s but %s has --%s %s: they must name one file; "+
				"make the two agree, then run the migration again", kaneadUnit, pair[0], a, edgeUnit, pair[1], e)
		}
	}

	// existing is what is at confPath now; start is the document the flags
	// are applied over, which --config could point elsewhere or turn off.
	existing, err := readOptional(opts.confPath)
	if err != nil {
		return report, err
	}
	start, startPath := existing, opts.confPath
	switch conf, _ := agentSet["config"].(string); conf {
	case "":
	case "off":
		start = nil
	default:
		if start, err = os.ReadFile(conf); err != nil { // #nosec G304; the path the unit named
			return report, fmt.Errorf("--config: %w", err)
		}
		if conf != opts.confPath {
			startPath = conf
			report.sideFiles = append(report.sideFiles, conf)
		}
	}
	ed, err := nodeconfig.NewEditor(startPath, start)
	if err != nil {
		return report, err
	}

	applyLegacyFlags(ed, legacyAgentFlags, agentSet)
	if err := applyAgentSpecials(ed, agentSet, &report); err != nil {
		return report, err
	}
	applyLegacyFlags(ed, legacyEdgeFlags, edgeSet)
	// The environment is applied only where the file is silent. Unlike the
	// flags it stays in the unit, so beating the file would undo a later
	// edit every time the migration is run again.
	if repo != "" && !ed.Has("upgrade", "repo") {
		ed.Set(cty.StringVal(repo), "upgrade", "repo")
	}
	if requireSig && !ed.Has("upgrade", "require_signature") {
		ed.Set(cty.True, "upgrade", "require_signature")
	}
	if repo != "" || requireSig {
		report.notes = append(report.notes, "Environment= KANEA_REPO and KANEA_REQUIRE_SIGNATURE in "+
			kaneadUnit+" are no longer read; the upgrade stanza replaces them.")
	}

	result := tidyBlankLines(ed.Bytes())
	parsed, err := nodeconfig.Parse(opts.confPath, result)
	if err != nil {
		return report, fmt.Errorf("the migrated configuration does not load: %w", err)
	}
	if len(parsed.Ignored) > 0 {
		report.notes = append(report.notes,
			"Not read by this version (kept as written): "+strings.Join(parsed.Ignored, ", "))
	}
	confChanged := !bytes.Equal(result, existing)
	if !hasFlags && !confChanged {
		report.sideFiles = nil
		report.notes = []string{"Neither unit carries flags."}
		return report, nil
	}

	report.migrated = true
	report.config = result
	report.agentExecStart = "ExecStart=" + agentBin + " agent"
	type rewrite struct {
		unit *legacyUnit
		body string
	}
	var rewrites []rewrite
	var renames []string
	if len(agentArgs) > 0 {
		body, err := agent.withExecStart(report.agentExecStart)
		if err != nil {
			return report, err
		}
		rewrites = append(rewrites, rewrite{agent, body})
		renames = append(renames, agent.execDropIns...)
	}
	if edgeU != nil {
		report.edgeExecStart = "ExecStart=" + edgeBin + " edge"
		if len(edgeArgs) > 0 {
			body, err := edgeU.withExecStart(report.edgeExecStart)
			if err != nil {
				return report, err
			}
			rewrites = append(rewrites, rewrite{edgeU, body})
			renames = append(renames, edgeU.execDropIns...)
		}
	}
	report.renamedDropIns = renames
	if opts.dryRun {
		return report, nil
	}

	if confChanged {
		if err := os.MkdirAll(filepath.Dir(opts.confPath), 0o755); err != nil { // #nosec G301; /etc/kanea is world-readable by design
			return report, fmt.Errorf("create %s: %w", filepath.Dir(opts.confPath), err)
		}
		if existing != nil {
			taken, err := backupOnce(opts.confPath+preMigrateSuffix, existing)
			if err != nil {
				return report, err
			}
			if taken {
				report.backup = opts.confPath + preMigrateSuffix
			}
		}
		if err := nodeconfig.WriteFile(opts.confPath, result); err != nil {
			return report, err
		}
	}
	for _, rw := range rewrites {
		if rw.body == rw.unit.content {
			continue
		}
		if err := replaceFile(rw.unit.path, []byte(rw.body), rw.unit.mode); err != nil {
			return report, err
		}
	}
	for _, path := range renames {
		if err := os.Rename(path, path+migratedSuffix); err != nil {
			return report, fmt.Errorf("retire drop-in: %w", err)
		}
	}
	return report, nil
}

// parseLegacyFlags parses one unit's arguments against its frozen table and
// returns the flags that were explicitly set, typed by kind.
func parseLegacyFlags(unit string, table []legacyFlag, args []string) (map[string]any, error) {
	fset := flag.NewFlagSet(unit, flag.ContinueOnError)
	fset.SetOutput(io.Discard)
	for _, f := range table {
		switch f.kind {
		case kindBool:
			fset.Bool(f.name, false, "")
		case kindInt:
			fset.Int(f.name, 0, "")
		case kindDuration:
			fset.Duration(f.name, 0, "")
		default:
			fset.String(f.name, "", "")
		}
	}
	if err := fset.Parse(args); err != nil {
		return nil, fmt.Errorf("%s: ExecStart: %w", unit, err)
	}
	if fset.NArg() > 0 {
		return nil, fmt.Errorf("%s: ExecStart: unexpected argument %q", unit, fset.Arg(0))
	}
	set := map[string]any{}
	fset.Visit(func(f *flag.Flag) {
		if getter, ok := f.Value.(flag.Getter); ok {
			set[f.Name] = getter.Get()
		}
	})
	return set, nil
}

// applyLegacyFlags writes every set flag that maps straight onto an
// attribute. Top-level attributes go first so that, in a new file, they sit
// above the stanzas rather than between them.
func applyLegacyFlags(ed *nodeconfig.Editor, table []legacyFlag, set map[string]any) {
	for _, topLevel := range []bool{true, false} {
		for _, f := range table {
			v, ok := set[f.name]
			if !ok || f.path == nil || (len(f.path) == 1) != topLevel {
				continue
			}
			switch f.kind {
			case kindBool:
				ed.Set(cty.BoolVal(v.(bool)), f.path...)
			case kindInt:
				ed.Set(cty.NumberIntVal(int64(v.(int))), f.path...)
			case kindDuration:
				ed.Set(cty.StringVal(v.(time.Duration).String()), f.path...)
			case kindList:
				items := splitList(v.(string))
				switch {
				case len(items) > 0:
					ed.Set(stringList(items), f.path...)
				case f.name == "dns-upstream":
					// An empty --dns-upstream deferred to the file.
				default:
					ed.Set(cty.ListValEmpty(cty.String), f.path...)
				}
			default:
				s := v.(string)
				switch {
				case s != "":
					ed.Set(cty.StringVal(s), f.path...)
				case f.name == "image-pull-policy":
					// An empty --image-pull-policy deferred to the file.
				default:
					// The flag beat the file, and an empty attribute is
					// an absent one.
					ed.Unset(f.path...)
				}
			}
		}
	}
}

// applyAgentSpecials handles the kanead flags that were not one attribute:
// the ones that named another file, replaced half a stanza, or took "off".
func applyAgentSpecials(ed *nodeconfig.Editor, set map[string]any, report *migrateReport) error {
	str := func(name string) string { s, _ := set[name].(string); return s }

	if raw := str("allowed-host-paths"); raw == "off" {
		ed.Set(cty.ListValEmpty(cty.String), "storage", "allowed_host_paths")
	} else if items := splitList(raw); len(items) > 0 {
		ed.Set(stringList(items), "storage", "allowed_host_paths")
	}

	// A side file replaced the node config's own blocks of that kind (or,
	// for provider and certificate, was the only place they were read
	// from), so those are dropped before its blocks are copied in. That
	// also makes a second run over a half-finished migration a no-op.
	fold := func(flagName string, types ...string) error {
		path := str(flagName)
		if path == "" {
			return nil
		}
		if path != "off" {
			src, err := os.ReadFile(path) // #nosec G304; the path the unit named
			if err != nil {
				return fmt.Errorf("--%s: %w", flagName, err)
			}
			for _, t := range types {
				ed.RemoveBlocks(t)
			}
			if err := ed.AppendBlocksFrom(path, src, types...); err != nil {
				return fmt.Errorf("--%s: %w", flagName, err)
			}
			report.sideFiles = append(report.sideFiles, path)
			return nil
		}
		for _, t := range types {
			ed.RemoveBlocks(t)
		}
		return nil
	}
	if err := fold("passthrough-config", "device", "socket"); err != nil {
		return err
	}
	if err := fold("secrets-providers-config", "provider"); err != nil {
		return err
	}
	if err := fold("tls-certs-config", "certificate"); err != nil {
		return err
	}

	if listen := str("listen"); listen != "" {
		for _, attr := range bindAPIAttrs {
			ed.Unset("bind", attr)
		}
		if listen != "none" {
			ed.Set(cty.StringVal(listen), "bind", "api_addr")
			if cert := str("listen-cert"); cert != "" {
				ed.Set(cty.StringVal(cert), "bind", "api_cert")
			}
			if key := str("listen-key"); key != "" {
				ed.Set(cty.StringVal(key), "bind", "api_key")
			}
		}
	}

	switch gc := str("image-gc"); gc {
	case "":
	case "on":
		ed.Set(cty.True, "images", "gc", "enabled")
	case "off":
		ed.Set(cty.False, "images", "gc", "enabled")
	default:
		return fmt.Errorf("--image-gc %q: want on or off", gc)
	}
	return nil
}

// legacyUnit is one systemd unit as the migration sees it: the main file's
// bytes, and what the file plus its drop-ins add up to.
type legacyUnit struct {
	name    string
	path    string
	content string
	mode    fs.FileMode
	entries []unitEntry // the main file's assignments
	// execStart is the effective command line; env the effective
	// Environment= assignments.
	execStart string
	env       map[string]string
	// execDropIns are the drop-ins holding an ExecStart= line, in name
	// order.
	execDropIns []string
}

// unitEntry is one Key=Value assignment and the physical lines it spans
// (more than one when continued with a trailing backslash).
type unitEntry struct {
	key, value string
	start, end int
}

// parseUnit lists a unit file's assignments. Sections are not tracked: the
// keys the migration reads exist in one section only.
func parseUnit(content string) []unitEntry {
	var entries []unitEntry
	lines := strings.SplitAfter(content, "\n")
	isComment := func(s string) bool { return strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") }
	for i := 0; i < len(lines); i++ {
		start := i
		line := strings.TrimSpace(lines[i])
		if line == "" || isComment(line) || strings.HasPrefix(line, "[") {
			continue
		}
		for strings.HasSuffix(line, `\`) {
			line = strings.TrimSuffix(line, `\`)
			if i+1 >= len(lines) {
				break
			}
			i++
			next := strings.TrimSpace(lines[i])
			if isComment(next) {
				// systemd skips a comment inside a continued line.
				line += `\`
				continue
			}
			line += " " + next
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		entries = append(entries, unitEntry{
			key: strings.TrimSpace(key), value: strings.TrimSpace(value), start: start, end: i,
		})
	}
	return entries
}

// readUnit loads <dir>/<name> and its <name>.d/*.conf drop-ins in name
// order, the order systemd applies them in.
func readUnit(dir, name string) (*legacyUnit, error) {
	path := filepath.Join(dir, name)
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path) // #nosec G304; a unit in the operator-named unit directory
	if err != nil {
		return nil, err
	}
	u := &legacyUnit{
		name: name, path: path, content: string(raw), mode: info.Mode().Perm(),
		env: map[string]string{},
	}
	u.entries = parseUnit(u.content)
	if err := u.absorb(u.entries); err != nil {
		return nil, err
	}

	dropIns, err := filepath.Glob(filepath.Join(path+".d", "*.conf"))
	if err != nil {
		return nil, err
	}
	sort.Strings(dropIns)
	for _, dropIn := range dropIns {
		raw, err := os.ReadFile(dropIn) // #nosec G304; a drop-in of the unit above
		if err != nil {
			return nil, err
		}
		entries := parseUnit(string(raw))
		if err := u.absorb(entries); err != nil {
			return nil, fmt.Errorf("%s: %w", dropIn, err)
		}
		for _, e := range entries {
			if e.key == "ExecStart" {
				u.execDropIns = append(u.execDropIns, dropIn)
				break
			}
		}
	}
	return u, nil
}

// absorb applies one file's assignments with systemd's rules: an empty
// assignment resets, the last one otherwise wins.
func (u *legacyUnit) absorb(entries []unitEntry) error {
	for _, e := range entries {
		switch e.key {
		case "ExecStart":
			u.execStart = e.value
		case "Environment":
			if e.value == "" {
				u.env = map[string]string{}
				continue
			}
			assignments, err := splitArgv(e.value)
			if err != nil {
				return fmt.Errorf("%s: Environment=: %w", u.name, err)
			}
			for _, a := range assignments {
				if k, v, ok := strings.Cut(a, "="); ok {
					u.env[k] = v
				}
			}
		}
	}
	return nil
}

// legacyArgs splits the effective ExecStart into the binary token and the
// arguments after the subcommand, which are the legacy flags.
func (u *legacyUnit) legacyArgs(sub string) (string, []string, error) {
	argv, err := splitArgv(u.execStart)
	if err != nil {
		return "", nil, fmt.Errorf("%s: ExecStart: %w", u.name, err)
	}
	if len(argv) < 2 || argv[1] != sub {
		return "", nil, fmt.Errorf("%s: ExecStart %q does not run `kanea %s`: not a unit this command can migrate",
			u.name, u.execStart, sub)
	}
	return argv[0], argv[2:], nil
}

// withExecStart returns the main unit file with its ExecStart assignment
// replaced by line and every other byte as it was.
func (u *legacyUnit) withExecStart(line string) (string, error) {
	lines := strings.SplitAfter(u.content, "\n")
	replaced := false
	var b strings.Builder
	next := 0
	for _, e := range u.entries {
		if e.key != "ExecStart" {
			continue
		}
		for _, l := range lines[next:e.start] {
			b.WriteString(l)
		}
		if !replaced {
			b.WriteString(line)
			if strings.HasSuffix(lines[e.end], "\n") {
				b.WriteString("\n")
			}
			replaced = true
		}
		next = e.end + 1
	}
	if !replaced {
		return "", fmt.Errorf("%s has no ExecStart line of its own (a drop-in supplies it): "+
			"add `%s` to its [Service] section, then run the migration again", u.path, line)
	}
	for _, l := range lines[next:] {
		b.WriteString(l)
	}
	return b.String(), nil
}

// splitArgv splits a command line on whitespace, honouring "…" and '…'
// quoting and a backslash before a quote, a backslash or a space. systemd's
// specifiers and variable expansion are not interpreted: no unit Kanea
// wrote used them.
func splitArgv(line string) ([]string, error) {
	var argv []string
	var cur strings.Builder
	inWord := false
	var quote rune
	runes := []rune(line)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote != 0:
			switch {
			case r == quote:
				quote = 0
			case r == '\\' && quote == '"' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\'):
				i++
				cur.WriteRune(runes[i])
			default:
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				argv = append(argv, cur.String())
				cur.Reset()
				inWord = false
			}
		case r == '\\' && i+1 < len(runes) && strings.ContainsRune(`"'\ `, runes[i+1]):
			i++
			cur.WriteRune(runes[i])
			inWord = true
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote in %q", quote, line)
	}
	if inWord {
		argv = append(argv, cur.String())
	}
	return argv, nil
}

// tidyBlankLines removes what moving whole blocks leaves behind: the blank
// line a removed block sat under, and the one a copied block's body opens
// with. Besides looking wrong they would accumulate, and converting the same
// flags twice must give the same bytes. A document with a heredoc is left
// alone: a blank line inside one is data.
func tidyBlankLines(src []byte) []byte {
	if bytes.Contains(src, []byte("<<")) {
		return src
	}
	var out []string
	for _, line := range strings.Split(string(src), "\n") {
		if strings.TrimSpace(line) == "" {
			if len(out) == 0 {
				continue
			}
			if prev := out[len(out)-1]; prev == "" || strings.HasSuffix(prev, "{") {
				continue
			}
			out = append(out, "")
			continue
		}
		out = append(out, line)
	}
	for len(out) > 0 && out[len(out)-1] == "" {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// readOptional reads a file that may not exist; absent is nil, nil.
func readOptional(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) // #nosec G304; the node config path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if raw == nil {
		raw = []byte{}
	}
	return raw, nil
}

// backupOnce writes data to path unless something is already there: the
// first copy is the operator's original and a later run must not replace it.
func backupOnce(path string, data []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) // #nosec G302 G304; a copy of the world-readable node config
	if errors.Is(err, fs.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("back up node config: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return false, errors.Join(fmt.Errorf("back up node config: %w", err), f.Close(), os.Remove(path))
	}
	if err := f.Close(); err != nil {
		return false, fmt.Errorf("back up node config: %w", err)
	}
	return true, nil
}

// replaceFile swaps path's content through a temporary file beside it, so a
// unit is never left half-written.
func replaceFile(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("rewrite %s: %w", path, err)
	}
	fail := func(err error) error {
		return errors.Join(fmt.Errorf("rewrite %s: %w", path, err), tmp.Close(), os.Remove(tmp.Name()))
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return errors.Join(fmt.Errorf("rewrite %s: %w", path, err), os.Remove(tmp.Name()))
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.Join(fmt.Errorf("rewrite %s: %w", path, err), os.Remove(tmp.Name()))
	}
	return nil
}
