package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/hashicorp/hcl/v2"
	"golang.org/x/term"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/runtime"
	"github.com/m18h/kanea/internal/scaling"
)

// loadSpec parses the job spec files given on the command line, or builds a
// one-service spec from the --image/--name/--project flags. PRD §6 calls the
// image-only path first-class: `kanea run --image=nginx --name web` must work
// with no file at all. Selectors (PRD v1.57) narrow the converted desired
// state to a project or a service: after parsing and validation, so the
// filter can never change what the spec means, only how much of it is sent.
// The third return is the set of projects the spec declares a `project` block
// for: the scope a prune may claim authority over (v1.83). It is the block
// list rather than the projects of the declared services, so a spec can say
// "this project is now empty" as its last service is removed.
func loadSpec(
	files []string, sels []selector, image, name, project string, count int,
	nodeVars nodeVarsResult,
) ([]reconciler.Desired, []gitops.Config, []string, error) {
	if image != "" {
		if len(files) > 0 || len(sels) > 0 {
			return nil, nil, nil, errors.New(
				"--image builds its one service from --name and --project; spec files and selectors do not combine with it")
		}
		if name == "" || project == "" {
			return nil, nil, nil, errors.New("--image also needs --name and --project")
		}
		return []reconciler.Desired{{
			Project: project,
			Service: name,
			Count:   count,
			Image:   image,
			// CPU and memory stay zero; unbounded, like a spec with no
			// resources block (R11, v1.58). Pids keeps its cap everywhere.
			Resources: runtime.Resources{PidsLimit: DefaultPidsLimit},
		}}, nil, nil, nil // --image declares no project block: never authoritative
	}
	if len(files) == 0 {
		if len(sels) > 0 {
			return nil, nil, nil, fmt.Errorf(
				"selector %q needs a spec file to select from; give at least one file", sels[0].raw)
		}
		return nil, nil, nil, errors.New("give a job spec file, or --image with --name and --project")
	}

	spec, diags := jobspec.ParseFiles(jobspec.Options{NodeVars: nodeVars.vars, Files: dirReader{}}, files...)
	if diags.HasErrors() {
		// Diagnostics carry file:line:column; print them as-is and fail without
		// adding a second, vaguer error on top.
		if _, werr := fmt.Fprint(os.Stderr, jobspec.FormatDiagnostics(diags)); werr != nil {
			return nil, nil, nil, werr
		}
		// An unknown variable after a failed vars fetch may just be the
		// daemon being unreachable: say so instead of leaving the two
		// failures indistinguishable (R30).
		if nodeVars.err != nil && hasUnknownVariable(diags) {
			fmt.Fprintf(os.Stderr,
				"note: the node's shared variables were unavailable (%v); a variable defined in /etc/kanea/kanea.hcl would report as unknown here\n",
				nodeVars.err)
		}
		return nil, nil, nil, fmt.Errorf("%d problem(s) in the job spec", len(diags))
	}
	desired, err := toDesired(spec)
	if err != nil {
		return nil, nil, nil, err
	}
	pipelines := pipelineConfigs(spec)
	if len(sels) > 0 {
		if desired, err = filterDesired(desired, sels); err != nil {
			return nil, nil, nil, err
		}
		pipelines = filterPipelines(pipelines, desired)
	}
	declared := make([]string, 0, len(spec.Projects))
	for _, p := range spec.Projects {
		declared = append(declared, p.Name)
	}
	return desired, pipelines, declared, nil
}

// nodeVarsResult is a best-effort GET /v1/vars: the map when the daemon
// answered, the error when it did not. A fetch failure is never fatal on its
// own: a spec whose variables all resolve locally parses exactly as offline
// as it did before v1.63, but it is remembered, so an unknown-variable
// diagnostic can say the defaults were missing rather than wrong.
type nodeVarsResult struct {
	vars map[string]string
	err  error
}

// fetchNodeVars reads the node's shared variables (R30), best-effort; the
// checkPublishedPorts discipline: an older daemon without the route, or no
// daemon at all, degrades the parse rather than failing it.
func fetchNodeVars(ctx context.Context, client *api.Client) nodeVarsResult {
	vars, err := client.Vars(ctx)
	return nodeVarsResult{vars: vars, err: err}
}

// hasUnknownVariable reports whether any diagnostic is HCL's unknown-variable
// error: the one a missing node default presents as.
func hasUnknownVariable(diags hcl.Diagnostics) bool {
	for _, d := range diags {
		if d.Summary == "Unknown variable" {
			return true
		}
	}
	return false
}

// pipelineConfigs extracts the per-project pipeline configuration from a spec.
//
// The git and build blocks travel with the services they were declared beside:
// a daemon that received the services alone would hold a service with a build
// block it has no source for, which is a service nobody can rebuild.
func pipelineConfigs(spec *jobspec.Spec) []gitops.Config {
	seen := map[string]bool{}
	var out []gitops.Config
	for _, svc := range spec.Services {
		if seen[svc.Project] {
			continue
		}
		seen[svc.Project] = true
		if cfg, ok := gitops.ConfigFromSpec(spec, svc.Project); ok {
			out = append(out, cfg)
		}
	}
	return out
}

// runRun implements `kanea run`.
func runRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	ep := endpointFlags(fs)
	image := fs.String("image", "", "run a single image without a spec file")
	name := fs.String("name", "", "service name (with --image)")
	project := fs.String("project", "", "project name (with --image)")
	count := fs.Int("count", 1, "alloc count (with --image)")
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for allocs to run; 0 to skip")
	removeOrphans := fs.Bool("remove-orphans", false,
		"delete services in this spec's projects that the spec no longer declares")
	yes := fs.Bool("yes", false, "apply without asking; implied when stdin is not a terminal")
	yesShort := fs.Bool("y", false, "alias for --yes")
	if err := fs.Parse(args); err != nil {
		return err
	}

	files, sels, err := splitFilesAndSelectors(fs.Args())
	if err != nil {
		return err
	}
	// The client exists before the parse (v1.63): the spec may lean on the
	// node's shared variables, fetched best-effort like the port pre-check.
	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}
	desired, pipelines, declared, err := loadSpec(files, sels, *image, *name, *project, *count,
		fetchNodeVars(ctx, client))
	if err != nil {
		return err
	}
	prune, err := pruneScope(*removeOrphans, declared, sels, *image)
	if err != nil {
		return err
	}

	// The same read `kanea plan` performs, computed by the same function, so a
	// plan and the run that follows it cannot disagree about what would happen.
	current, changes, err := planChanges(ctx, client, desired, prune)
	if err != nil {
		return err
	}
	// `--image` builds a Desired from nothing, so applying one over a service
	// that carries more than it can express silently deletes the difference.
	// Refused rather than warned: the loss is invisible until something stops
	// answering, and `kanea deploy` is the verb that was wanted.
	if *image != "" {
		if err := checkImageWouldNotClobber(current, desired); err != nil {
			return err
		}
	}
	if err := checkPublishedPorts(ctx, client, desired); err != nil {
		return err
	}

	o := newOut()
	writeChanges(o, changes, pipelines)
	// A prompt is for a person. A piped or redirected stdin is a script, and a
	// script must never be asked a question: that is resolveListen's rule
	// (init_bootstrap.go), and it is what keeps every CI recipe written against
	// an older kanea working exactly as it did.
	interactive := !*yes && !*yesShort && len(changes) > 0 &&
		term.IsTerminal(int(os.Stdin.Fd()))
	ok, err := confirmApply(o, bufio.NewReader(os.Stdin), interactive)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("aborted; nothing was applied")
	}

	resp, err := client.ApplyScoped(ctx, api.ApplyRequest{
		Services: desired, Pipelines: pipelines, PruneProjects: prune,
	})
	if err != nil {
		return err
	}
	// A blank line between the preview and what came of it, since without a
	// prompt (--yes, or CI) the two would otherwise run together.
	o.println()
	for _, svc := range resp.Applied {
		o.printf("applied %s\n", svc)
	}
	for _, svc := range resp.Removed {
		o.printf("removed %s\n", svc)
	}
	if len(resp.Removed) > 0 {
		// Said every time, because it is the reason a mistaken prune is
		// survivable and the reason a deliberate one does not free any disk.
		o.printf("\n%d service(s) removed. Volume data was not deleted.\n", len(resp.Removed))
	}
	if err := o.Err(); err != nil {
		return err
	}
	if *wait <= 0 {
		return nil
	}
	return waitForRunning(ctx, client, desired, *wait)
}

// planChanges is the one pre-apply read: the stored services, and what an apply
// would do to them.
//
// `kanea plan` and `kanea run` both go through it, because the alternative is
// two implementations of "what would change", and they drift into a plan that
// does not match the apply that follows it. It returns the stored listing too,
// so a caller that also needs it (`--image`'s clobber check) does not fetch the
// same thing twice.
//
// A listing error is fatal here, as it has always been in `plan`: the preview
// is the only thing standing between a typo and a rolling restart, and quietly
// skipping it because the daemon did not answer would drop that gate at exactly
// the moment something is already wrong.
func planChanges(
	ctx context.Context, client *api.Client, desired []reconciler.Desired, prune []string,
) ([]reconciler.Desired, []reconciler.ServiceChange, error) {
	current, err := client.Services(ctx)
	if err != nil {
		return nil, nil, err
	}
	return current, reconciler.Changes(current, desired, prune), nil
}

// writeChanges renders a change set: the per-service blocks, then the verdict.
//
// Shared by plan and run so the preview a person confirms is byte-identical to
// the one they asked for a moment earlier.
func writeChanges(o *out, changes []reconciler.ServiceChange, pipelines []gitops.Config) {
	if len(changes) == 0 {
		o.println("No changes. Desired state matches the declared spec.")
		if note := pipelineNote(pipelines); note != "" {
			o.println(note)
		}
		return
	}
	for _, line := range reconciler.RenderChanges(changes) {
		o.println(line)
	}
	o.printf("\n%s\n", planSummary(changes))
	if note := pipelineNote(pipelines); note != "" {
		o.println(note)
	}
}

// planSummary is the one-line verdict under the blocks: how much would change,
// and how much of it replaces containers that are serving traffic right now.
func planSummary(changes []reconciler.ServiceChange) string {
	n := reconciler.CountChanges(changes)
	var parts []string
	for _, p := range []struct {
		n    int
		verb string
	}{{n.Create, "create"}, {n.Update, "update"}, {n.Destroy, "destroy"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.verb))
		}
	}
	line := fmt.Sprintf("Plan: %d change(s) - %s", len(changes), strings.Join(parts, ", "))
	if n.Rolling > 0 {
		line += fmt.Sprintf("; %d replace running allocs", n.Rolling)
	}
	return line + "."
}

// pipelineNote names the non-service state an apply also writes.
//
// It is a statement of what is being sent rather than a diff, because nothing
// reads a stored pipeline config back: ApplyResponse answers with service names
// only, and there is no route for the rest. Saying this much is still worth it
// - a git source, a build target or a notification route changing with no line
// on screen is the silence this whole feature exists to end - and a real diff
// of it is an API route somebody can add later.
func pipelineNote(pipelines []gitops.Config) string {
	if len(pipelines) == 0 {
		return ""
	}
	names := make([]string, 0, len(pipelines))
	for _, p := range pipelines {
		names = append(names, p.Project)
	}
	sort.Strings(names)
	return fmt.Sprintf(
		"pipelines: %s - the git source, build specs and notification routes are written as declared",
		strings.Join(names, ", "))
}

// confirmApply asks before an apply acts, and answers yes for anything that is
// not a person.
//
// The default is yes, so the common case is one keypress: this is a preview of
// something the operator just typed, not a destructive-action gate. Anything
// other than an empty line, y or yes aborts, including a typo, because the cost
// of re-running `kanea run` is a second and the cost of a wrong yes is a
// rolling restart.
func confirmApply(o *out, in *bufio.Reader, interactive bool) (bool, error) {
	if !interactive {
		return true, nil
	}
	o.printf("\nApply? [Y/n] ")
	// Flushed before the read, or the prompt sits in the tabwriter behind a
	// cursor waiting for an answer to a question nobody can see.
	if err := o.Err(); err != nil {
		return false, err
	}
	line, err := in.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	if err != nil && answer == "" {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	return answer == "" || answer == "y" || answer == "yes", nil
}

// pruneScope decides what a `--remove-orphans` apply may claim authority over.
//
// The two refusals are the point of the function. A selector filters the
// desired state before it is sent, so the request no longer represents the
// whole project and claiming authority over it would delete every unselected
// sibling; `--image` declares no project block at all. Both are refused rather
// than silently narrowed, following the doctrine checkImageWouldNotClobber
// already sets: refuse where the alternative is a silent deletion.
func pruneScope(removeOrphans bool, declared []string, sels []selector, image string) ([]string, error) {
	if !removeOrphans {
		return nil, nil
	}
	if image != "" {
		return nil, errors.New(
			"--remove-orphans needs a spec file: --image declares one service and no project, " +
				"so it can never say what a project should contain")
	}
	if len(sels) > 0 {
		return nil, fmt.Errorf(
			"--remove-orphans cannot be combined with a selector (%s): a selector sends part of "+
				"the spec, so the apply cannot claim to be the whole of any project. "+
				"Re-run without the selector to prune, or without --remove-orphans to apply just that scope",
			sels[0].raw)
	}
	if len(declared) == 0 {
		return nil, errors.New("--remove-orphans: the spec declares no project block to be authoritative for")
	}
	return declared, nil
}

// checkImageWouldNotClobber refuses a `--image` apply that would delete what
// the stored record carries.
//
// `--image` is a first-class path (PRD §6.2) for creating a bare service, and
// re-running the same command on the same bare service must stay idempotent.
// So this refuses on loss, not on existence: if the stored record holds
// something the synthetic one cannot express, the apply would drop it, and
// that is invisible until traffic stops arriving.
func checkImageWouldNotClobber(existing, desired []reconciler.Desired) error {
	for _, want := range desired {
		for _, have := range existing {
			if have.Project != want.Project || have.Service != want.Service {
				continue
			}
			if lost := fieldsLostByImageApply(have); len(lost) > 0 {
				return fmt.Errorf(
					"%s/%s already declares %s, which `--image` cannot express and would delete.\n"+
						"  To change the image and keep the rest: kanea deploy %s/%s %s\n"+
						"  To replace the service wholesale: apply the spec file that declares it",
					have.Project, have.Service, strings.Join(lost, ", "),
					have.Project, have.Service, want.Image)
			}
		}
	}
	return nil
}

// fieldsLostByImageApply names what a --image apply would drop from a record,
// in the vocabulary the spec uses, so the message reads like the file someone
// wrote rather than like a struct.
func fieldsLostByImageApply(d reconciler.Desired) []string {
	var lost []string
	add := func(cond bool, name string) {
		if cond {
			lost = append(lost, name)
		}
	}
	add(len(d.Ports) > 0, "ports")
	add(d.Expose != nil || len(d.ExtraExposes) > 0, "expose")
	add(len(d.Env) > 0, "env")
	add(len(d.Volumes) > 0, "volumes")
	add(len(d.Devices) > 0, "device grants")
	add(len(d.Sockets) > 0, "socket grants")
	add(d.Check != nil, "health check")
	add(d.Scaling != nil, "scaling")
	add(len(d.Capabilities) > 0, "capabilities")
	add(len(d.Init) > 0, "init containers")
	add(len(d.Files) > 0, "config files")
	add(d.Function != nil, "function config")
	return lost
}

// waitForRunning polls until every desired alloc is running, so `kanea run`
// exits meaning "it is up" rather than "it was requested". Progress is
// reported as state transitions, and on failure or timeout the stragglers are
// listed by name with the detail `kanea ps` would give: the answer the user
// would otherwise have to go fetch.
func waitForRunning(ctx context.Context, client *api.Client, desired []reconciler.Desired, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	want := 0
	for _, d := range desired {
		want += d.Count
	}
	if want == 0 {
		return nil
	}

	o := newOut()
	// The first poll is a silent baseline: a service that was already up must
	// not re-announce itself on every converged re-apply.
	last := map[string]reconciler.AllocState{}
	seeded := false
	for {
		allocs, err := client.Allocs(ctx, "", "")
		if err != nil {
			return err
		}
		ours := allocs[:0]
		running, failed := 0, 0
		for _, a := range allocs {
			if !isDesiredAlloc(desired, a) {
				continue
			}
			ours = append(ours, a)
			switch a.State {
			case reconciler.AllocRunning:
				running++
			case reconciler.AllocFailed:
				failed++
			}
		}
		for _, a := range ours {
			if seeded && a.State != last[a.ID] {
				switch a.State {
				case reconciler.AllocRunning:
					o.printf("%s running (%d/%d)\n", a.ID, running, want)
				case reconciler.AllocBackoff, reconciler.AllocFailed:
					o.printf("%s %s\n", a.ID, allocStateLabel(a))
				}
			}
			last[a.ID] = a.State
		}
		seeded = true
		if running >= want {
			o.printf("%d/%d allocs running\n", running, want)
			return o.Err()
		}
		if failed > 0 || time.Now().After(deadline) {
			printStragglers(o, desired, ours)
			if err := o.Err(); err != nil {
				return err
			}
			if failed > 0 {
				return fmt.Errorf("%d alloc(s) failed with %d/%d running", failed, running, want)
			}
			return fmt.Errorf("timed out after %s with %d/%d allocs running", timeout, running, want)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// printStragglers lists every desired slot that is not up, with the state
// detail `kanea ps` would show: including declared slots the reconciler has
// not created yet, which have no record to explain themselves with.
func printStragglers(o *out, desired []reconciler.Desired, allocs []reconciler.AllocRecord) {
	byID := map[string]reconciler.AllocRecord{}
	for _, a := range allocs {
		byID[a.ID] = a
	}
	crashed := false
	o.println("\nstill not running:")
	o.table()
	for _, d := range desired {
		for i := 0; i < d.Count; i++ {
			id := reconciler.AllocID(d.Project, d.Service, i)
			a, ok := byID[id]
			switch {
			case !ok:
				o.printf("  %s\tpending (not created)\n", id)
			case a.State != reconciler.AllocRunning:
				o.printf("  %s\t%s\n", id, allocStateLabel(a))
				crashed = crashed || a.State == reconciler.AllocBackoff || a.State == reconciler.AllocFailed
			case !a.Healthy && !a.LastProbeAt.IsZero():
				o.printf("  %s\trunning (unhealthy)\n", id)
			}
		}
	}
	o.endTable()
	if crashed {
		o.println("`kanea logs <project>/<service>` shows the crash output")
	}
}

func isDesiredAlloc(desired []reconciler.Desired, alloc reconciler.AllocRecord) bool {
	for _, d := range desired {
		if d.Project == alloc.Project && d.Service == alloc.Service {
			return true
		}
	}
	return false
}

// runPlan implements `kanea plan`: the dry-run diff PRD §6.2 R4 requires.
func runPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	ep := endpointFlags(fs)
	image := fs.String("image", "", "plan a single image without a spec file")
	name := fs.String("name", "", "service name (with --image)")
	project := fs.String("project", "", "project name (with --image)")
	count := fs.Int("count", 1, "alloc count (with --image)")
	removeOrphans := fs.Bool("remove-orphans", false,
		"also show what `kanea run --remove-orphans` would delete")
	if err := fs.Parse(args); err != nil {
		return err
	}

	files, sels, err := splitFilesAndSelectors(fs.Args())
	if err != nil {
		return err
	}
	// The client exists before the parse (v1.63), for the node-vars fetch.
	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}
	desired, pipelines, declared, err := loadSpec(files, sels, *image, *name, *project, *count,
		fetchNodeVars(ctx, client))
	if err != nil {
		return err
	}
	// The same scope the apply would claim, computed the same way, so a plan
	// and the run that follows it cannot disagree about what would go.
	prune, err := pruneScope(*removeOrphans, declared, sels, *image)
	if err != nil {
		return err
	}

	_, changes, err := planChanges(ctx, client, desired, prune)
	if err != nil {
		return err
	}
	if err := checkPublishedPorts(ctx, client, desired); err != nil {
		return err
	}

	o := newOut()
	if len(sels) > 0 {
		// A filtered "No changes" must not read as "the whole file is
		// converged" (PRD v1.57).
		raws := make([]string, len(sels))
		for i, sel := range sels {
			raws[i] = sel.raw
		}
		o.printf("Scope: %s\n\n", strings.Join(raws, ", "))
	}
	writeChanges(o, changes, pipelines)
	if len(changes) > 0 {
		o.println("Run `kanea run` to apply.")
	}
	return o.Err()
}

// runPs implements `kanea ps`.
func runPs(args []string) error {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "filter by project")
	service := fs.String("service", "", "filter by service")
	all := fs.Bool("a", false,
		"also show what is declared but not running: stopped services, uncreated slots")
	allLong := fs.Bool("all", false, "alias for -a")
	if err := fs.Parse(args); err != nil {
		return err
	}
	showAll := *all || *allLong

	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}
	allocs, err := client.Allocs(ctx, *project, *service)
	if err != nil {
		return err
	}

	// A removed alloc leaves no record on purpose (only failed-and-declared
	// ones persist to explain themselves), so a stopped service is invisible
	// to the plain table. -a re-derives those rows from the declarations.
	var ghosts []psGhost
	if showAll {
		services, err := client.Services(ctx)
		if err != nil {
			return err
		}
		ghosts = declaredButAbsent(services, allocs, *project, *service)
	}

	o := newOut()
	if len(allocs) == 0 && len(ghosts) == 0 {
		if showAll {
			o.println("No allocs and no declared services.")
		} else {
			o.println("No allocs. (`kanea ps -a` also shows stopped services.)")
		}
		return o.Err()
	}

	o.table()
	o.println("ALLOC\tPROJECT\tSERVICE\tSTATE\tRESTARTS\tIMAGE\tAGE")
	for _, a := range allocs {
		age := "-"
		if !a.CreatedAt.IsZero() {
			age = shortDuration(time.Since(a.CreatedAt))
		}
		o.printf("%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			a.ID, a.Project, a.Service, allocStateLabel(a), a.Restarts, a.Image, age)
	}
	for _, g := range ghosts {
		o.printf("%s\t%s\t%s\t%s\t-\t%s\t-\n",
			g.id, g.project, g.service, g.state, g.image)
	}
	return o.Err()
}

// allocStateLabel renders an alloc's state with the detail a status line
// needs: a failed or backing-off alloc must explain itself; `ps` and the
// `run` wait are where a user looks first when something is not running;
// and a running-but-failing alloc is the case that most needs distinguishing:
// the process is up, so "running" alone is misleading, and it is why anything
// depending on it has not started.
func allocStateLabel(a reconciler.AllocRecord) string {
	switch a.State {
	case reconciler.AllocFailed:
		return fmt.Sprintf("failed (exit %d)", a.LastExitCode)
	case reconciler.AllocBackoff:
		return fmt.Sprintf("backoff (exit %d, retry in %s)",
			a.LastExitCode, shortDuration(time.Until(a.NextRestartAt)))
	case reconciler.AllocRunning:
		if !a.Healthy && !a.LastProbeAt.IsZero() {
			return "running (unhealthy)"
		}
	}
	return string(a.State)
}

// psGhost is a `ps -a` row for something declared with no alloc record.
type psGhost struct {
	id, project, service, state, image string
}

// declaredButAbsent derives the -a rows: a service scaled to zero is one
// "stopped" row, and a declared slot with no record is "pending"; the
// reconciler simply has not created it yet.
func declaredButAbsent(
	services []reconciler.Desired, allocs []reconciler.AllocRecord,
	project, service string,
) []psGhost {
	present := map[string]bool{}
	for _, a := range allocs {
		present[reconciler.AllocID(a.Project, a.Service, a.Index)] = true
	}
	var ghosts []psGhost
	for _, svc := range services {
		if project != "" && svc.Project != project {
			continue
		}
		if service != "" && svc.Service != service {
			continue
		}
		if svc.Count == 0 {
			ghosts = append(ghosts, psGhost{
				id: "-", project: svc.Project, service: svc.Service,
				state: "stopped (count 0)", image: svc.RunImage(),
			})
			continue
		}
		for i := 0; i < svc.Count; i++ {
			if id := reconciler.AllocID(svc.Project, svc.Service, i); !present[id] {
				ghosts = append(ghosts, psGhost{
					id: id, project: svc.Project, service: svc.Service,
					state: "pending (not created)", image: svc.RunImage(),
				})
			}
		}
	}
	return ghosts
}

// runStatus implements `kanea status`: the one-screen answer to "is the
// platform healthy, and is anything unhappy?".
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "filter by project")
	traffic := fs.Bool("traffic", false,
		"show the edge's status-code and byte breakdown per service (PRD §9.1.1)")
	asJSON := fs.Bool("json", false, "emit the status as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("usage: kanea status [--project P] [[project/]service]")
	}

	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	services, err := client.Services(ctx)
	if err != nil {
		return err
	}

	// The optional service argument §16.2 has always documented (v1.56):
	// resolved like every other service-targeting command, it narrows the
	// table to one service. The full list is still fetched, because the
	// "waiting for" verdict below needs the dependencies' rows to reason
	// about, even when they are not displayed.
	proj, svcName := *project, ""
	if fs.NArg() == 1 {
		target, err := findService(services, *project, fs.Arg(0))
		if err != nil {
			return err
		}
		proj, svcName = target.Project, target.Service
	}
	visible := visibleServices(services, proj, svcName)

	allocs, err := client.Allocs(ctx, proj, "")
	if err != nil {
		return err
	}

	if *asJSON {
		return writeStatusJSON(ctx, client, health, visible, allocs, "", *traffic)
	}

	o := newOut()
	o.printf("kanead    %s (store index %d)\n", health.Status, health.StoreIndex)
	o.printf("endpoint  %s\n", client.Target())
	o.println()

	if len(services) == 0 {
		o.println("No services declared. Try `kanea run --image=... --name=... --project=...`.")
		return o.Err()
	}

	// Per service: desired count against what is actually running, plus the
	// unhappy states called out by name. A status screen that only prints
	// totals hides exactly the thing the operator is looking for.
	counts := tallyAllocs(allocs)

	o.table()
	o.println("SERVICE\tDESIRED\tRUNNING\tHEALTH\tIMAGE")
	unhealthy := 0
	for _, svc := range visible {
		key := svc.Project + "/" + svc.Service
		t := counts[key]
		if t == nil {
			t = &tally{}
		}
		health, settled := serviceHealth(svc.Count, t.running, t.backoff, t.failed, t.unhealthy)
		// "starting" is not an answer when a service has been gated for
		// minutes. Say what it is waiting for, or the operator has to read the
		// agent log to find out why nothing is happening.
		if t.running == 0 && t.backoff == 0 && t.failed == 0 {
			if blocked := blockedOn(svc, services, counts); len(blocked) > 0 {
				health = "waiting for " + strings.Join(blocked, ", ")
				settled = false
			}
		}
		if !settled {
			unhealthy++
		}
		o.printf("%s\t%d\t%d\t%s\t%s\n", key, svc.Count, t.running, health, svc.Image)
	}
	if err := o.Err(); err != nil {
		return err
	}

	if *traffic {
		if err := printTraffic(ctx, client, visible, ""); err != nil {
			return err
		}
	}

	tail := newOut()
	tail.println()
	if unhealthy == 0 {
		tail.println("All services healthy.")
	} else {
		tail.printf("%d service(s) need attention: see `kanea ps` and `kanea logs <service>`.\n", unhealthy)
	}
	return tail.Err()
}

// visibleServices narrows the status table to a project, a single service, or
// neither. It filters what is *displayed* only: the caller keeps the full
// list for the dependency reasoning, because "waiting for db" is an answer a
// scoped view still owes even when db's own row is not shown.
func visibleServices(services []reconciler.Desired, project, service string) []reconciler.Desired {
	out := make([]reconciler.Desired, 0, len(services))
	for _, svc := range services {
		if project != "" && svc.Project != project {
			continue
		}
		if service != "" && svc.Service != service {
			continue
		}
		out = append(out, svc)
	}
	return out
}

// tallyAllocs groups alloc records by service and by state.
//
// Shared by the table and the --json form so the two cannot disagree about
// whether a service is healthy, which is exactly the sort of drift a second
// copy of this loop would introduce.
func tallyAllocs(allocs []reconciler.AllocRecord) map[string]*tally {
	counts := map[string]*tally{}
	for _, a := range allocs {
		key := a.Project + "/" + a.Service
		if counts[key] == nil {
			counts[key] = &tally{}
		}
		switch a.State {
		case reconciler.AllocRunning:
			counts[key].running++
			// Probed() is the guard: Healthy is only ever written by a probe,
			// so a service that declares no check has it false forever.
			if !a.Healthy && a.Probed() {
				counts[key].unhealthy++
			}
		case reconciler.AllocBackoff:
			counts[key].backoff++
		case reconciler.AllocFailed:
			counts[key].failed++
		default:
			counts[key].other++
		}
	}
	return counts
}

// printTraffic renders the edge's per-service breakdown (§9.1.1).
//
// Only services the edge has actually seen appear. A service with no `expose`
// block has no edge traffic by definition, and a row of zeroes for it would
// read as "nobody is using this" rather than "this was never reachable from
// outside".
func printTraffic(ctx context.Context, client *api.Client,
	services []reconciler.Desired, project string,
) error {
	type row struct {
		service  string
		sample   scaling.ServiceBreakdown
		hasCodes bool
	}
	var rows []row
	for _, svc := range services {
		if project != "" && svc.Project != project {
			continue
		}
		sample, err := client.Stats(ctx, svc.Project, svc.Service)
		if err != nil {
			// One service's sample failing must not take the whole table down:
			// the status command is what an operator runs when things are
			// already wrong.
			continue
		}
		if sample.Edge == nil {
			continue
		}
		rows = append(rows, row{
			service:  svc.Project + "/" + svc.Service,
			sample:   *sample.Edge,
			hasCodes: len(sample.Edge.Codes) > 0,
		})
	}

	o := newOut()
	o.println()
	if len(rows) == 0 {
		o.println("No edge traffic recorded. Either nothing is exposed, or kanea-edge is not being scraped.")
		return o.Err()
	}

	o.table()
	o.println("SERVICE\tREQUESTS\tCODES\tIN\tOUT")
	for _, r := range rows {
		total := 0.0
		for _, n := range r.sample.Codes {
			total += n
		}
		o.printf("%s\t%.0f\t%s\t%s\t%s\n", r.service, total, formatCodes(r.sample.Codes),
			formatBytes(r.sample.RequestBytes), formatBytes(r.sample.ResponseBytes))
	}
	return o.Err()
}

// formatCodes renders a status-code breakdown, worst first.
//
// Descending by code rather than by count on purpose: a 502 that happened
// twice is what the operator is looking for, and sorting by volume would bury
// it under a million 200s.
func formatCodes(codes map[string]float64) string {
	if len(codes) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(codes))
	for code := range codes {
		keys = append(keys, code)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))

	parts := make([]string, 0, len(keys))
	for _, code := range keys {
		parts = append(parts, fmt.Sprintf("%s=%.0f", code, codes[code]))
	}
	return strings.Join(parts, " ")
}

// formatBytes renders a byte count in the largest unit that keeps it readable.
func formatBytes(n float64) string {
	const unit = 1024.0
	switch {
	case n < unit:
		return fmt.Sprintf("%.0fB", n)
	case n < unit*unit:
		return fmt.Sprintf("%.1fKiB", n/unit)
	case n < unit*unit*unit:
		return fmt.Sprintf("%.1fMiB", n/(unit*unit))
	default:
		return fmt.Sprintf("%.1fGiB", n/(unit*unit*unit))
	}
}

// statusJSON is `kanea status --json`.
type statusJSON struct {
	Status     string `json:"status"`
	StoreIndex uint64 `json:"store_index"`
	// Socket keeps its name and stays populated locally, so a script that
	// already reads `.socket` is unbroken; it is omitted on a remote client,
	// which has no socket, rather than carrying a URL under that key.
	Socket string `json:"socket,omitempty"`
	// Endpoint is what the client actually talked to, socket or origin.
	Endpoint string             `json:"endpoint"`
	Services []statusServiceRow `json:"services"`
}

type statusServiceRow struct {
	Project string `json:"project"`
	Service string `json:"service"`
	Desired int    `json:"desired"`
	Running int    `json:"running"`
	Health  string `json:"health"`
	Settled bool   `json:"settled"`
	Image   string `json:"image,omitempty"`
	// Edge is present only with --traffic, and only for a service the edge has
	// seen. Absent means "not measured", never "no traffic".
	Edge *scaling.ServiceBreakdown `json:"edge,omitempty"`
}

// writeStatusJSON emits the machine-readable form (§21 UX: every CLI mutation
// has --json, and the read commands that feed a script want it too).
func writeStatusJSON(ctx context.Context, client *api.Client, health api.Health,
	services []reconciler.Desired, allocs []reconciler.AllocRecord,
	project string, traffic bool,
) error {
	counts := tallyAllocs(allocs)

	out := statusJSON{
		Status:     health.Status,
		StoreIndex: health.StoreIndex,
		Socket:     client.Socket(),
		Endpoint:   client.Target(),
		Services:   []statusServiceRow{},
	}
	for _, svc := range services {
		if project != "" && svc.Project != project {
			continue
		}
		t := counts[svc.Project+"/"+svc.Service]
		if t == nil {
			t = &tally{}
		}
		state, settled := serviceHealth(svc.Count, t.running, t.backoff, t.failed, t.unhealthy)
		row := statusServiceRow{
			Project: svc.Project, Service: svc.Service,
			Desired: svc.Count, Running: t.running,
			Health: state, Settled: settled, Image: svc.Image,
		}
		if traffic {
			if sample, err := client.Stats(ctx, svc.Project, svc.Service); err == nil {
				row.Edge = sample.Edge
			}
		}
		out.Services = append(out.Services, row)
	}

	body, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	o := newOut()
	o.printf("%s\n", body)
	return o.Err()
}

// serviceHealth summarises one service for `kanea status`, and reports whether
// it has settled. "Settled" means running exactly matches desired with nothing
// failed or restarting: running *more* than desired is mid-convergence (a
// scale-in or a stop still draining), not health.
func serviceHealth(desiredCount, running, backoff, failed, unhealthy int) (string, bool) {
	switch {
	case failed > 0:
		return fmt.Sprintf("%d failed", failed), false
	case backoff > 0:
		return fmt.Sprintf("%d restarting", backoff), false
	case unhealthy > 0:
		// Counted before the "starting" case: an alloc that is up but failing
		// its check is a different problem from one that has not started, and
		// reporting it as "starting" would suggest waiting is enough.
		return fmt.Sprintf("%d unhealthy", unhealthy), false
	case running < desiredCount:
		return "starting", false
	case running > desiredCount:
		return "stopping", false
	case desiredCount == 0:
		return "stopped", true
	default:
		return "ok", true
	}
}

// runLogs implements `kanea logs`.
func runLogs(args []string) error {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "filter by project")
	alloc := fs.String("alloc", "", "a single alloc id")
	follow := fs.Bool("f", false, "follow the stream")
	tail := fs.Int("tail", 0, "show only the last N lines before following")
	container := fs.String("c", "",
		"read an init container's log instead of the task's, by its block name (PRD §6.2 R32)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	service := ""
	if fs.NArg() > 0 {
		service = fs.Arg(0)
	}
	if service == "" && *alloc == "" && *project == "" {
		return errors.New("give a service name, --alloc, or --project")
	}

	// Ctrl-C ends a follow cleanly rather than dumping a stack of errors.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := ep.client()
	if err != nil {
		return err
	}

	// A service name resolves like every other service-targeting command
	// (v1.56): `media/plex` used to be passed through as a literal (a name
	// no service can have) and matched nothing.
	proj := *project
	if service != "" {
		services, err := client.Services(ctx)
		if err != nil {
			return err
		}
		target, err := findService(services, *project, service)
		if err != nil {
			return err
		}
		proj, service = target.Project, target.Service
	}

	return client.Logs(ctx, api.LogOptions{
		Project: proj, Service: service, AllocID: *alloc,
		Follow: *follow, Tail: *tail, Container: *container,
		// Scrubbed (K-45): a workload's log line can carry terminal control
		// sequences, and the operator's terminal is not the workload's.
	}, scrubTerminal{os.Stdout})
}

// runStop implements `kanea stop`: scale a service to zero, or remove it.
func runStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "project name")
	remove := fs.Bool("rm", false, "also delete the service declaration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea stop [--project P] [--rm] <[project/]service>")
	}
	service := fs.Arg(0)

	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}

	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	target, err := findService(services, *project, service)
	if err != nil {
		return err
	}

	if *remove {
		if _, err := client.DeleteService(ctx, target.Project, target.Service); err != nil {
			return err
		}
		o := newOut()
		o.printf("removed %s/%s\n", target.Project, target.Service)
		return o.Err()
	}

	// Scaling to zero keeps the declaration, so `kanea run` (or a scale up)
	// brings it back without re-declaring it.
	target.Count = 0
	if _, err := client.Apply(ctx, []reconciler.Desired{target}, nil); err != nil {
		return err
	}
	o := newOut()
	o.printf("stopped %s/%s (count 0; use --rm to delete the service)\n",
		target.Project, target.Service)
	return o.Err()
}

// runStart implements `kanea start`: scale a stopped service back up; stop's
// counterpart, through the same scale route. The daemon does not remember the
// pre-stop count (a stopped record says zero, PRD v1.54), so the default is
// one replica; and a service already running is left exactly as it is,
// because start is idempotent, never a second spelling of scale.
func runStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "project name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("usage: kanea start [--project P] <[project/]service> [count]")
	}
	count := 1
	if fs.NArg() == 2 {
		n, err := strconv.Atoi(fs.Arg(1))
		if err != nil || n < 1 {
			return fmt.Errorf("count %q must be a number, one or more", fs.Arg(1))
		}
		count = n
	}

	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}

	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	target, err := findService(services, *project, fs.Arg(0))
	if err != nil {
		return err
	}

	o := newOut()
	if target.Count > 0 {
		o.printf("%s/%s is already running (count %d); use kanea scale to change it\n",
			target.Project, target.Service, target.Count)
		return o.Err()
	}

	// An autoscaled service is started at its own floor: the server refuses a
	// count outside the declared bounds (it would be undone within seconds),
	// so defaulting to 1 against min = 2 would be an error nobody typed. An
	// explicit count is passed through and meets the server's refusal, which
	// names the bounds.
	autoscaled := target.Scaling != nil && target.Scaling.Max > 0 && len(target.Scaling.Metrics) > 0
	if fs.NArg() != 2 && autoscaled && target.Scaling.Min > count {
		count = target.Scaling.Min
	}

	if _, err := client.Scale(ctx, target.Project, target.Service, count); err != nil {
		return err
	}
	if fs.NArg() == 2 {
		o.printf("started %s/%s (count %d)\n", target.Project, target.Service, count)
	} else {
		o.printf("started %s/%s (count %d; kanea scale sets more)\n",
			target.Project, target.Service, count)
	}
	if autoscaled {
		o.printf("note: %s/%s autoscales between %d and %d; it converges to its own count\n",
			target.Project, target.Service, target.Scaling.Min, target.Scaling.Max)
	}
	return o.Err()
}

// runDeploy implements `kanea deploy`: point an existing service at a new
// image and leave everything else exactly as declared (PRD v1.82, §16.2).
//
// Read the record, change one field, write the whole thing back. There is no
// route that sets an image on its own, and sending back what was read is what
// makes that safe: a deploy can never silently drop a field this command does
// not know about. It is the recipe MCP's deploy_service already uses, which is
// why the two cannot drift into disagreeing about what a deploy is.
//
// `kanea run --image` is emphatically not this: it builds a Desired from
// scratch, so over an existing service it drops ports, env, volumes and the
// rest. That is why this command exists.
func runDeploy(args []string) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "project name")
	wait := fs.Duration("wait", 60*time.Second,
		"how long to wait for the new image to be running")
	noWait := fs.Bool("no-wait", false, "return once the change is accepted, without waiting")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: kanea deploy [--project P] <[project/]service> <image>")
	}
	image := strings.TrimSpace(fs.Arg(1))
	if image == "" {
		return errors.New("deploy: an image reference is required")
	}

	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}
	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	target, err := findService(services, *project, fs.Arg(0))
	if err != nil {
		return err
	}

	o := newOut()
	// Re-running a pipeline on an unchanged commit is normal and is not an
	// error. Nothing pinned means nothing else to converge to, so there is
	// genuinely no work; a pin present means the running digest may differ from
	// what Image names, and the apply is worth making.
	if target.Image == image && target.PinnedImage == "" {
		o.printf("%s/%s already declares %s; nothing to do\n",
			target.Project, target.Service, image)
		return o.Err()
	}

	previous := target.Image
	target.Image = image
	if _, err := client.Apply(ctx, []reconciler.Desired{target}, nil); err != nil {
		return err
	}
	if previous == "" {
		o.printf("deploying %s/%s -> %s\n", target.Project, target.Service, image)
	} else {
		o.printf("deploying %s/%s: %s -> %s\n", target.Project, target.Service, previous, image)
	}

	if *noWait {
		return o.Err()
	}
	// Waiting by default is what makes this usable in CI: a pipeline should go
	// red when the new image does not come up, not when someone reads the logs
	// the next morning.
	if err := waitForRunning(ctx, client, []reconciler.Desired{target}, *wait); err != nil {
		return err
	}
	o.printf("%s/%s is running %s\n", target.Project, target.Service, image)
	return o.Err()
}

// runRestart implements `kanea restart`: ask the server to bump the service's
// generation, which rolls its allocs through the update policy; the same
// route the dashboard and MCP's restart_service have always used. It is also
// the way out of an exhausted restart budget: the bump is a new spec hash,
// and R29 ties the crash-restart count to the hash that spent it.
func runRestart(args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "project name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea restart [--project P] <[project/]service>")
	}

	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}

	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	target, err := findService(services, *project, fs.Arg(0))
	if err != nil {
		return err
	}

	if _, err := client.Restart(ctx, target.Project, target.Service); err != nil {
		return err
	}
	o := newOut()
	o.printf("restart requested for %s/%s; allocs roll through the update policy\n",
		target.Project, target.Service)
	return o.Err()
}

// runScale sets a service's replica count.
//
// The same operation the autoscaler performs, through the same route: a manual
// scale and an automatic one cannot disagree about what the count means,
// because there is only one way to change it.
func runScale(args []string) error {
	fs := flag.NewFlagSet("scale", flag.ContinueOnError)
	ep := endpointFlags(fs)
	project := fs.String("project", "", "project name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: kanea scale [--project P] <[project/]service> <count>")
	}
	count, err := strconv.Atoi(fs.Arg(1))
	if err != nil || count < 0 {
		return fmt.Errorf("count %q must be a number, zero or more", fs.Arg(1))
	}

	ctx := context.Background()
	client, err := ep.client()
	if err != nil {
		return err
	}

	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	target, err := findService(services, *project, fs.Arg(0))
	if err != nil {
		return err
	}

	if _, err := client.Scale(ctx, target.Project, target.Service, count); err != nil {
		return err
	}

	o := newOut()
	o.printf("scaled %s/%s from %d to %d\n", target.Project, target.Service, target.Count, count)
	if p := target.Scaling; p != nil && p.Max > 0 && len(p.Metrics) > 0 {
		// Worth saying out loud: the autoscaler owns this number, and a manual
		// count that its rules disagree with will not survive the next pass.
		o.printf("note: %s/%s autoscales between %d and %d; this count holds only "+
			"until the next evaluation disagrees\n",
			target.Project, target.Service, p.Min, p.Max)
	}
	return o.Err()
}

// findService resolves a service name, requiring --project only when the name
// is ambiguous across projects. The documented `project/service` form (PRD
// §16.2: `kanea stop shop/web`) is resolved here, so every command that looks
// a service up accepts it; a service name is a DNS-1123 label and can never
// contain a slash, so the split is unambiguous.
func findService(services []reconciler.Desired, project, name string) (reconciler.Desired, error) {
	if p, s, ok := strings.Cut(name, "/"); ok {
		if project != "" && project != p {
			return reconciler.Desired{}, fmt.Errorf(
				"--project %s disagrees with %q; drop one of them", project, name)
		}
		project, name = p, s
	}
	var matches []reconciler.Desired
	for _, svc := range services {
		if svc.Service != name {
			continue
		}
		if project != "" && svc.Project != project {
			continue
		}
		matches = append(matches, svc)
	}
	switch len(matches) {
	case 0:
		if project != "" {
			return reconciler.Desired{}, fmt.Errorf("no service %q in project %q", name, project)
		}
		return reconciler.Desired{}, fmt.Errorf("no service %q", name)
	case 1:
		return matches[0], nil
	default:
		projects := make([]string, 0, len(matches))
		for _, m := range matches {
			projects = append(projects, m.Project)
		}
		sort.Strings(projects)
		return reconciler.Desired{}, fmt.Errorf(
			"service %q exists in projects %s; use --project", name, strings.Join(projects, ", "))
	}
}

// out is the CLI's stdout writer. It records the first write error so a command
// can report it once at the end rather than checking every call: the usual
// cause is a closed pipe (`kanea ps | head`), and the repo's lint policy
// (errcheck check-blank) rightly refuses to let those be discarded silently.
type out struct {
	w   io.Writer
	tw  *tabwriter.Writer
	err error
}

func newOut() *out { return &out{w: os.Stdout} }

func (o *out) printf(format string, args ...any) {
	if o.err != nil {
		return
	}
	_, o.err = fmt.Fprintf(o.writer(), format, args...)
}

func (o *out) println(args ...any) {
	if o.err != nil {
		return
	}
	_, o.err = fmt.Fprintln(o.writer(), args...)
}

// table switches subsequent writes to a tabwriter; Err flushes it.
func (o *out) table() {
	o.tw = tabwriter.NewWriter(o.w, 0, 0, 2, ' ', 0)
}

// endTable flushes a table and returns subsequent writes to plain output,
// for screens that mix a table with prose sections (`kanea describe`).
func (o *out) endTable() {
	if o.tw == nil {
		return
	}
	if err := o.tw.Flush(); err != nil && o.err == nil {
		o.err = err
	}
	o.tw = nil
}

func (o *out) writer() io.Writer {
	if o.tw != nil {
		return o.tw
	}
	return o.w
}

// Err returns the first write error, flushing any pending table first.
func (o *out) Err() error {
	if o.tw != nil {
		if err := o.tw.Flush(); err != nil && o.err == nil {
			o.err = err
		}
	}
	return o.err
}

// shortDuration renders a duration the way a status column should: coarse and
// short, never "1h23m45.6789s".
func shortDuration(d time.Duration) string {
	if d < 0 {
		return "0s"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// tally counts a service's allocs by state, for `kanea status`.
type tally struct {
	running, backoff, failed, unhealthy, other int
}

// blockedOn reports which of a service's dependencies cannot yet serve,
// mirroring the reconciler's gate (R10) for display.
//
// It is recomputed here rather than reported by the agent because a gated alloc
// has no record to carry a reason: it does not exist yet, which is precisely
// the thing being explained.
func blockedOn(svc reconciler.Desired, services []reconciler.Desired, counts map[string]*tally) []string {
	declared := make(map[string]reconciler.Desired, len(services))
	for _, other := range services {
		declared[other.Project+"/"+other.Service] = other
	}

	var blocked []string
	for _, dep := range svc.DependsOn {
		key := svc.Project + "/" + dep
		target, ok := declared[key]
		if !ok {
			// Removed under a running spec; the reconciler starts anyway rather
			// than waiting forever on something that will never appear.
			continue
		}
		if target.Count == 0 {
			continue // deliberately scaled to nothing: vacuously satisfied
		}
		t := counts[key]
		if t == nil || t.running < target.Count || t.unhealthy > 0 {
			blocked = append(blocked, dep)
		}
	}
	sort.Strings(blocked)
	return blocked
}

// checkPublishedPorts asks the node which ports a spec may bind (R22).
//
// A courtesy, not the boundary: handleApply re-checks, because a GitOps sync
// never comes through the CLI. What it buys is the refusal landing in front of
// the person who typed the port, at plan, rather than at apply.
//
// A node that cannot answer is not a failure. An older daemon has no such route
// and a spec with no published ports has nothing to ask about, so silence here
// costs only the better error location.
func checkPublishedPorts(ctx context.Context, client *api.Client, desired []reconciler.Desired) error {
	var publishes bool
	for _, d := range desired {
		if len(d.Publish) > 0 {
			publishes = true
			break
		}
	}
	if !publishes {
		return nil
	}
	policy, err := client.EdgePolicy(ctx)
	if err != nil {
		return nil //nolint:nilerr // an older daemon still enforces this at apply
	}
	for _, d := range desired {
		name := d.Project + "/" + d.Service
		for _, p := range d.Publish {
			if !policy.Enabled {
				return fmt.Errorf("%s publishes node port %d, and this node has published "+
					"ports turned off (--publish-ports off)", name, p.Host)
			}
			if !policy.Allows(p.Host) {
				return fmt.Errorf("%s publishes node port %d, which this node does not allow "+
					"(--publish-ports %s). Which ports may be claimed belongs to whoever owns "+
					"the machine, not to a spec", name, p.Host, policy.Spec)
			}
		}
	}
	return nil
}
