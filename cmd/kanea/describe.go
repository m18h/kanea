package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
)

// runDescribe implements `kanea describe`: the one-service deep view
// (PRD v1.54, §16.2) — the declared spec beside what is actually true.
//
// Assembled client-side from the routes that already exist (services, allocs,
// stats, events): the same reads the dashboard makes, so the CLI cannot know
// anything the API does not serve — §16.3's no-side-channels rule, applied to
// the read path.
func runDescribe(args []string) error {
	fs := flag.NewFlagSet("describe", flag.ContinueOnError)
	socket := socketFlag(fs)
	project := fs.String("project", "", "project name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: kanea describe [--project P] <[project/]service>")
	}

	ctx := context.Background()
	client := api.NewClient(*socket)
	services, err := client.Services(ctx)
	if err != nil {
		return err
	}
	svc, err := findService(services, *project, fs.Arg(0))
	if err != nil {
		return err
	}
	allocs, err := client.Allocs(ctx, svc.Project, svc.Service)
	if err != nil {
		return err
	}
	// Stats and events are decoration on the answer, not the answer: a
	// describe that fails because the TS has nothing would be backwards.
	stats, statsErr := client.Stats(ctx, svc.Project, svc.Service)
	events, eventsErr := client.Events(ctx, svc.Project, 200)

	o := newOut()
	describeSpec(o, svc)
	describeRoutes(o, svc)
	describeStorage(o, svc)
	describeAllocs(o, svc, allocs)
	if statsErr == nil {
		describeStats(o, stats)
	}
	if eventsErr == nil {
		describeEvents(o, svc.Service, events)
	}
	return o.Err()
}

func describeSpec(o *out, svc reconciler.Desired) {
	o.printf("Service      %s/%s\n", svc.Project, svc.Service)
	o.printf("Image        %s\n", svc.Image)
	if svc.PinnedImage != "" && svc.PinnedImage != svc.Image {
		checked := ""
		if !svc.ImageCheckedAt.IsZero() {
			checked = fmt.Sprintf(" (checked %s ago)", shortDuration(time.Since(svc.ImageCheckedAt)))
		}
		o.printf("Pinned       %s%s\n", svc.PinnedImage, checked)
	}
	o.printf("Count        %d\n", svc.Count)
	if svc.Runtime != "" {
		o.printf("Runtime      %s\n", svc.Runtime)
	}
	// The stored list is what was declared; an empty one means the R13
	// baseline for a runc service, and saying so beats printing nothing —
	// the difference between "default" and "none" is the whole feature.
	if len(svc.Capabilities) > 0 {
		o.printf("Capabilities %s\n", strings.Join(svc.Capabilities, ", "))
	} else if svc.Runtime == "" {
		o.printf("Capabilities baseline (default)\n")
	}
	if len(svc.DependsOn) > 0 {
		o.printf("Depends on   %s\n", strings.Join(svc.DependsOn, ", "))
	}
	update := svc.Update.Strategy
	if update == "" {
		update = "rolling"
	}
	if svc.Update.Auto {
		update += fmt.Sprintf(", auto every %s", svc.Update.Interval)
	}
	o.printf("Update       %s\n", update)
	if svc.Check != nil {
		check := svc.Check.Type
		if svc.Check.Path != "" {
			check += " " + svc.Check.Path
		}
		if svc.Check.Port != 0 {
			check += fmt.Sprintf(" :%d", svc.Check.Port)
		}
		if svc.Check.Interval > 0 {
			check += fmt.Sprintf(" every %s", svc.Check.Interval)
		}
		o.printf("Check        %s\n", check)
	}
	if svc.Generation != 0 {
		o.printf("Generation   %d\n", svc.Generation)
	}
}

func describeRoutes(o *out, svc reconciler.Desired) {
	exposes := svc.AllExposes()
	if len(exposes) == 0 && len(svc.Publish) == 0 {
		return
	}
	o.println()
	o.println("Routes")
	for _, e := range exposes {
		domains := strings.Join(e.Domains, ", ")
		if domains == "" {
			domains = "(auto FQDN)"
		}
		extras := []string{}
		if e.TLSMode != "" {
			extras = append(extras, "tls "+e.TLSMode)
		}
		if e.Protocol != "" {
			extras = append(extras, e.Protocol)
		}
		if e.Auth != nil {
			extras = append(extras, "auth")
		}
		suffix := ""
		if len(extras) > 0 {
			suffix = " (" + strings.Join(extras, ", ") + ")"
		}
		o.printf("  %s -> :%d%s\n", domains, e.Port, suffix)
	}
	for _, p := range svc.Publish {
		mode := p.Mode
		if mode == "" {
			mode = "http"
		}
		o.printf("  node :%d -> port %q (%s)\n", p.Host, p.Port, mode)
	}
}

func describeStorage(o *out, svc reconciler.Desired) {
	if len(svc.Volumes) == 0 && len(svc.Devices) == 0 && len(svc.Sockets) == 0 {
		return
	}
	o.println()
	o.println("Storage & grants")
	for _, v := range svc.Volumes {
		ro := ""
		if v.ReadOnly {
			ro = " (ro)"
		}
		o.printf("  volume %s: %s -> %s%s\n", v.Name, v.Storage, v.MountPath, ro)
	}
	for _, d := range svc.Devices {
		o.printf("  device %s: grant %q\n", d.Name, d.Grant)
	}
	for _, s := range svc.Sockets {
		o.printf("  socket %s: grant %q -> %s\n", s.Name, s.Grant, s.MountPath)
	}
}

func describeAllocs(o *out, svc reconciler.Desired, allocs []reconciler.AllocRecord) {
	o.println()
	if len(allocs) == 0 {
		if svc.Count == 0 {
			o.println("Allocs: none (stopped — count 0)")
		} else {
			o.println("Allocs: none yet")
		}
		return
	}
	o.println("Allocs")
	o.table()
	o.println("  ALLOC\tSTATE\tHEALTH\tRESTARTS\tREASON\tAGE")
	for _, a := range allocs {
		// Health renders absent as absent (§9.2): a check-free service reads
		// "-", never "unhealthy".
		health := "-"
		if a.Probed() {
			if a.Healthy {
				health = "ok"
			} else {
				health = "failing"
				if a.HealthMessage != "" {
					health = "failing: " + a.HealthMessage
				}
			}
		}
		age := "-"
		if !a.CreatedAt.IsZero() {
			age = shortDuration(time.Since(a.CreatedAt))
		}
		o.printf("  %s\t%s\t%s\t%d\t%s\t%s\n",
			a.ID, a.State, health, a.Restarts, allocReason(a), age)
	}
	o.endTable()
}

// reasonLabels renders a termination reason the way a person would say it (PRD
// v1.68, §17). The wire values stay snake_case like every other enum on the
// record; only the display differs.
var reasonLabels = map[reconciler.ExitReason]string{
	reconciler.ExitOOMKilled:         "OOMKilled",
	reconciler.ExitSignal:            "Signalled",
	reconciler.ExitError:             "Error",
	reconciler.ExitCompleted:         "Completed",
	reconciler.ExitImageFailed:       "ImageFailed",
	reconciler.ExitVolumeFailed:      "VolumeFailed",
	reconciler.ExitPassthroughFailed: "GrantFailed",
	reconciler.ExitNetworkFailed:     "NetworkFailed",
	reconciler.ExitCreateFailed:      "CreateFailed",
	reconciler.ExitStartFailed:       "StartFailed",
}

// allocReason renders why an alloc last stopped, or why it has not started.
//
// It is shown whatever the alloc's current state, because the STATE column is
// right beside it: a `running` row carrying "OOMKilled" says the alloc is up
// now and was killed for memory last time, which is the single most useful
// thing to know about a service that keeps coming back.
//
// A record from before v1.68 has a code and no reason, and renders as the code
// rather than as nothing — an upgrade must not make existing allocs less
// legible than they were.
func allocReason(a reconciler.AllocRecord) string {
	if a.LastExitReason == "" {
		if a.LastExitCode != 0 {
			return fmt.Sprintf("exit %d", a.LastExitCode)
		}
		return "-"
	}
	label := reasonLabels[a.LastExitReason]
	if label == "" {
		label = string(a.LastExitReason)
	}
	if a.LastExitMessage == "" {
		return label
	}
	return label + " — " + a.LastExitMessage
}

func describeStats(o *out, stats api.StatsSample) {
	// Absent is a gap, never zero (§9.2): a missing metric and an idle
	// service must not read the same.
	num := func(v *float64, unit string) string {
		if v == nil {
			return "-"
		}
		return fmt.Sprintf("%.1f%s", *v, unit)
	}
	o.println()
	o.printf("Stats now    cpu %s   memory %s   rps %s   p95 %s\n",
		num(stats.CPU, "%"), num(stats.Memory, "%"),
		num(stats.RPS, ""), num(stats.P95, "ms"))
}

func describeEvents(o *out, service string, events []notify.Event) {
	const keep = 10
	var mine []notify.Event
	for _, e := range events {
		// The server filtered by project; the service cut is ours. Events with
		// no service (project-wide) stay: a sync failure explains a deploy.
		if e.Service == "" || e.Service == service {
			mine = append(mine, e)
		}
		if len(mine) == keep {
			break
		}
	}
	if len(mine) == 0 {
		return
	}
	o.println()
	o.println("Recent events")
	for _, e := range mine {
		o.printf("  %s  %-22s %s\n", e.At.Local().Format("Jan 02 15:04:05"), e.Name, e.Message)
	}
}
