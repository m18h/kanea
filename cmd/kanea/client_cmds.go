package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/kanea-dev/kanea/internal/api"
	"github.com/kanea-dev/kanea/internal/jobspec"
	"github.com/kanea-dev/kanea/internal/reconciler"
	"github.com/kanea-dev/kanea/internal/runtime"
)

// socketFlag adds the shared --socket flag.
func socketFlag(fs *flag.FlagSet) *string {
	return fs.String("socket", api.DefaultSocket, "kanead control socket")
}

// loadSpec parses the job spec files given on the command line, or builds a
// one-service spec from the --image/--name/--project flags. PRD §6 calls the
// image-only path first-class: `kanea run --image=nginx --name web` must work
// with no file at all.
func loadSpec(files []string, image, name, project string, count int) ([]reconciler.Desired, error) {
	if image != "" {
		if name == "" || project == "" {
			return nil, errors.New("--image also needs --name and --project")
		}
		return []reconciler.Desired{{
			Project: project,
			Service: name,
			Count:   count,
			Image:   image,
			Resources: runtime.Resources{
				CPUMillis:   jobspec.DefaultCPU * 1000 / NominalCoreMHz,
				MemoryBytes: int64(jobspec.DefaultMemory) << 20,
				PidsLimit:   DefaultPidsLimit,
			},
		}}, nil
	}
	if len(files) == 0 {
		return nil, errors.New("give a job spec file, or --image with --name and --project")
	}

	spec, diags := jobspec.ParseFiles(jobspec.Options{}, files...)
	if diags.HasErrors() {
		// Diagnostics carry file:line:column; print them as-is and fail without
		// adding a second, vaguer error on top.
		if _, werr := fmt.Fprint(os.Stderr, jobspec.FormatDiagnostics(diags)); werr != nil {
			return nil, werr
		}
		return nil, fmt.Errorf("%d problem(s) in the job spec", len(diags))
	}
	return toDesired(spec)
}

// runRun implements `kanea run`.
func runRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	socket := socketFlag(fs)
	image := fs.String("image", "", "run a single image without a spec file")
	name := fs.String("name", "", "service name (with --image)")
	project := fs.String("project", "", "project name (with --image)")
	count := fs.Int("count", 1, "alloc count (with --image)")
	wait := fs.Duration("wait", 60*time.Second, "how long to wait for allocs to run; 0 to skip")
	if err := fs.Parse(args); err != nil {
		return err
	}

	desired, err := loadSpec(fs.Args(), *image, *name, *project, *count)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client := api.NewClient(*socket)
	resp, err := client.Apply(ctx, desired)
	if err != nil {
		return err
	}
	o := newOut()
	for _, svc := range resp.Applied {
		o.printf("applied %s\n", svc)
	}
	if err := o.Err(); err != nil {
		return err
	}
	if *wait <= 0 {
		return nil
	}
	return waitForRunning(ctx, client, desired, *wait)
}

// waitForRunning polls until every desired alloc is running, so `kanea run`
// exits meaning "it is up" rather than "it was requested".
func waitForRunning(ctx context.Context, client *api.Client, desired []reconciler.Desired, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	want := 0
	for _, d := range desired {
		want += d.Count
	}
	if want == 0 {
		return nil
	}

	for {
		allocs, err := client.Allocs(ctx, "", "")
		if err != nil {
			return err
		}
		running, failed := 0, 0
		for _, a := range allocs {
			if !isDesiredAlloc(desired, a) {
				continue
			}
			switch a.State {
			case reconciler.AllocRunning:
				running++
			case reconciler.AllocFailed:
				failed++
			}
		}
		if running >= want {
			o := newOut()
			o.printf("%d/%d allocs running\n", running, want)
			return o.Err()
		}
		if failed > 0 {
			return fmt.Errorf("%d alloc(s) failed; see `kanea logs` and `kanea ps`", failed)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s with %d/%d allocs running; see `kanea ps`",
				timeout, running, want)
		}
		time.Sleep(250 * time.Millisecond)
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
	socket := socketFlag(fs)
	image := fs.String("image", "", "plan a single image without a spec file")
	name := fs.String("name", "", "service name (with --image)")
	project := fs.String("project", "", "project name (with --image)")
	count := fs.Int("count", 1, "alloc count (with --image)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	desired, err := loadSpec(fs.Args(), *image, *name, *project, *count)
	if err != nil {
		return err
	}

	ctx := context.Background()
	client := api.NewClient(*socket)
	current, err := client.Services(ctx)
	if err != nil {
		return err
	}

	o := newOut()
	diff := diffServices(current, desired)
	if len(diff) == 0 {
		o.println("No changes. Desired state matches the declared spec.")
		return o.Err()
	}
	for _, line := range diff {
		o.println(line)
	}
	o.printf("\nPlan: %d change(s). Run `kanea run` to apply.\n", len(diff))
	return o.Err()
}

// diffServices renders a Nomad-style create/change/destroy summary. It compares
// only what a user declared, so an untouched service is not reported as a
// change just because the daemon added defaults.
func diffServices(current, desired []reconciler.Desired) []string {
	byKey := make(map[string]reconciler.Desired, len(current))
	for _, svc := range current {
		byKey[svc.Project+"/"+svc.Service] = svc
	}

	var out []string
	for _, want := range desired {
		key := want.Project + "/" + want.Service
		have, exists := byKey[key]
		if !exists {
			out = append(out, fmt.Sprintf("+ create %s (count %d, image %s)", key, want.Count, want.Image))
			continue
		}
		var changes []string
		if have.Image != want.Image {
			changes = append(changes, fmt.Sprintf("image %s -> %s", have.Image, want.Image))
		}
		if have.Count != want.Count {
			changes = append(changes, fmt.Sprintf("count %d -> %d", have.Count, want.Count))
		}
		if have.Resources != want.Resources {
			changes = append(changes, fmt.Sprintf("resources %+v -> %+v", have.Resources, want.Resources))
		}
		if !sameEnv(have.Env, want.Env) {
			changes = append(changes, "env changed")
		}
		if len(changes) > 0 {
			out = append(out, fmt.Sprintf("~ update %s (%s)", key, strings.Join(changes, ", ")))
		}
	}
	sort.Strings(out)
	return out
}

func sameEnv(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// runPs implements `kanea ps`.
func runPs(args []string) error {
	fs := flag.NewFlagSet("ps", flag.ContinueOnError)
	socket := socketFlag(fs)
	project := fs.String("project", "", "filter by project")
	service := fs.String("service", "", "filter by service")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := api.NewClient(*socket)
	allocs, err := client.Allocs(context.Background(), *project, *service)
	if err != nil {
		return err
	}
	o := newOut()
	if len(allocs) == 0 {
		o.println("No allocs.")
		return o.Err()
	}

	o.table()
	o.println("ALLOC\tPROJECT\tSERVICE\tSTATE\tRESTARTS\tIMAGE\tAGE")
	for _, a := range allocs {
		age := "-"
		if !a.CreatedAt.IsZero() {
			age = shortDuration(time.Since(a.CreatedAt))
		}
		state := string(a.State)
		// A failed or backing-off alloc must explain itself here: `ps` is where
		// a user looks first when something is not running.
		switch a.State {
		case reconciler.AllocFailed:
			state = fmt.Sprintf("failed (exit %d)", a.LastExitCode)
		case reconciler.AllocBackoff:
			state = fmt.Sprintf("backoff (exit %d, retry in %s)",
				a.LastExitCode, shortDuration(time.Until(a.NextRestartAt)))
		}
		o.printf("%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			a.ID, a.Project, a.Service, state, a.Restarts, a.Image, age)
	}
	return o.Err()
}

// runStatus implements `kanea status`: the one-screen answer to "is the
// platform healthy, and is anything unhappy?".
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	socket := socketFlag(fs)
	project := fs.String("project", "", "filter by project")
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()
	client := api.NewClient(*socket)

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	allocs, err := client.Allocs(ctx, *project, "")
	if err != nil {
		return err
	}

	o := newOut()
	o.printf("kanead    %s (store index %d)\n", health.Status, health.StoreIndex)
	o.printf("socket    %s\n", client.Socket())
	o.println()

	if len(services) == 0 {
		o.println("No services declared. Try `kanea run --image=... --name=... --project=...`.")
		return o.Err()
	}

	// Per service: desired count against what is actually running, plus the
	// unhappy states called out by name. A status screen that only prints
	// totals hides exactly the thing the operator is looking for.
	type tally struct {
		running, backoff, failed, other int
	}
	counts := map[string]*tally{}
	for _, a := range allocs {
		key := a.Project + "/" + a.Service
		if counts[key] == nil {
			counts[key] = &tally{}
		}
		switch a.State {
		case reconciler.AllocRunning:
			counts[key].running++
		case reconciler.AllocBackoff:
			counts[key].backoff++
		case reconciler.AllocFailed:
			counts[key].failed++
		default:
			counts[key].other++
		}
	}

	o.table()
	o.println("SERVICE\tDESIRED\tRUNNING\tHEALTH\tIMAGE")
	unhealthy := 0
	for _, svc := range services {
		key := svc.Project + "/" + svc.Service
		if *project != "" && svc.Project != *project {
			continue
		}
		t := counts[key]
		if t == nil {
			t = &tally{}
		}
		health, settled := serviceHealth(svc.Count, t.running, t.backoff, t.failed)
		if !settled {
			unhealthy++
		}
		o.printf("%s\t%d\t%d\t%s\t%s\n", key, svc.Count, t.running, health, svc.Image)
	}
	if err := o.Err(); err != nil {
		return err
	}

	tail := newOut()
	tail.println()
	if unhealthy == 0 {
		tail.println("All services healthy.")
	} else {
		tail.printf("%d service(s) need attention — see `kanea ps` and `kanea logs <service>`.\n", unhealthy)
	}
	return tail.Err()
}

// serviceHealth summarises one service for `kanea status`, and reports whether
// it has settled. "Settled" means running exactly matches desired with nothing
// failed or restarting — running *more* than desired is mid-convergence (a
// scale-in or a stop still draining), not health.
func serviceHealth(desiredCount, running, backoff, failed int) (string, bool) {
	switch {
	case failed > 0:
		return fmt.Sprintf("%d failed", failed), false
	case backoff > 0:
		return fmt.Sprintf("%d restarting", backoff), false
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
	socket := socketFlag(fs)
	project := fs.String("project", "", "filter by project")
	alloc := fs.String("alloc", "", "a single alloc id")
	follow := fs.Bool("f", false, "follow the stream")
	tail := fs.Int("tail", 0, "show only the last N lines before following")
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

	client := api.NewClient(*socket)
	return client.Logs(ctx, api.LogOptions{
		Project: *project, Service: service, AllocID: *alloc,
		Follow: *follow, Tail: *tail,
	}, os.Stdout)
}

// runStop implements `kanea stop`: scale a service to zero, or remove it.
func runStop(args []string) error {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	socket := socketFlag(fs)
	project := fs.String("project", "", "project name")
	remove := fs.Bool("rm", false, "also delete the service declaration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea stop [--project P] [--rm] <service>")
	}
	service := fs.Arg(0)

	ctx := context.Background()
	client := api.NewClient(*socket)

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
	if _, err := client.Apply(ctx, []reconciler.Desired{target}); err != nil {
		return err
	}
	o := newOut()
	o.printf("stopped %s/%s (count 0; use --rm to delete the service)\n",
		target.Project, target.Service)
	return o.Err()
}

// findService resolves a service name, requiring --project only when the name
// is ambiguous across projects.
func findService(services []reconciler.Desired, project, name string) (reconciler.Desired, error) {
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
// can report it once at the end rather than checking every call — the usual
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
