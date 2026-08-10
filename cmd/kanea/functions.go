package main

// The functions glue (PRD v1.39): the invoker's target source over the Store,
// the sink tee that hands it the notification dispatcher's feed, and the
// `kanea functions` CLI.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/functions"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/reconciler"
	"github.com/m18h/kanea/internal/store"
)

// functionTargets implements functions.Source over the Store: desired records
// with triggers, joined with the VIP the allocator assigned. Every URL is
// derived here — the spec has no field for one (R26), which is the whole SSRF
// story: reaching an address requires writing the VIP allocator.
type functionTargets struct {
	store store.Store
}

func (f functionTargets) Targets(ctx context.Context) ([]functions.Target, error) {
	services, err := listDesired(ctx, f.store)
	if err != nil {
		return nil, err
	}

	var out []functions.Target
	for _, d := range services {
		fn := d.Function
		if fn == nil || (len(fn.Events) == 0 && len(fn.Crons) == 0) {
			continue
		}
		port := functionPort(d)
		if port == 0 {
			continue // no declared port: nothing to dial
		}
		vip, _, err := store.GetValue[string](ctx, f.store, store.KindKV,
			reconciler.VIPKey(d.Project, d.Service))
		if err != nil || vip == "" {
			// No frontend yet — the reconciler has not converged this service.
			// The next wake reloads; skipping beats dialling nothing.
			continue
		}
		target := functions.Target{
			Project: d.Project, Service: d.Service,
			BaseURL:    fmt.Sprintf("http://%s:%d", vip, port),
			SigningRef: fn.SigningRef,
		}
		for _, ev := range fn.Events {
			target.Events = append(target.Events, functions.EventTrigger{On: ev.On, Path: ev.Path})
		}
		for _, cr := range fn.Crons {
			target.Crons = append(target.Crons, functions.CronTrigger{Schedule: cr.Schedule, Path: cr.Path})
		}
		out = append(out, target)
	}
	return out, nil
}

// functionPort is the lowered function's one declared port, named "http".
func functionPort(d reconciler.Desired) int {
	for _, p := range d.Ports {
		if p.Name == "http" {
			return p.Container
		}
	}
	if len(d.Ports) > 0 {
		return d.Ports[0].Container
	}
	return 0
}

// listDesired pages through every service record.
func listDesired(ctx context.Context, st store.Store) ([]reconciler.Desired, error) {
	var out []reconciler.Desired
	var after string
	for {
		values, page, err := store.ListValues[reconciler.Desired](ctx, st,
			store.KindService, store.ListOptions{After: after, Limit: 200})
		if err != nil {
			return nil, fmt.Errorf("list services: %w", err)
		}
		out = append(out, values...)
		if !page.More {
			return out, nil
		}
		after = page.NextAfter
	}
}

// teeSink fans the dispatcher's feed to a second consumer. The feed is the
// record and comes first, always; the invoker is attached after construction
// and before the dispatcher's goroutine starts, so no lock is needed — the
// goroutine start is the happens-before.
type teeSink struct {
	primary   notify.Sink
	secondary notify.Sink
}

func (t *teeSink) Record(ctx context.Context, e notify.Event) {
	t.primary.Record(ctx, e)
	if t.secondary != nil {
		t.secondary.Record(ctx, e)
	}
}

// runFunctions is `kanea functions list` (§16.2).
func runFunctions(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: kanea functions list [--json]")
	}
	fs := flag.NewFlagSet("functions list", flag.ContinueOnError)
	socket := socketFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	client := api.NewClient(*socket)
	resp, err := client.Functions(context.Background())
	if err != nil {
		return err
	}
	o := newOut()
	if *asJSON {
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		o.println(string(body))
		return o.Err()
	}
	if len(resp.Functions) == 0 {
		o.println("No functions.")
		return o.Err()
	}

	o.table()
	o.println("FUNCTION\tMODULE\tTRIGGERS\tINV/MIN\tMEM CAP\tSTATUS")
	for _, fn := range resp.Functions {
		rate := "-"
		if fn.InvocationsPerMinute != nil {
			rate = fmt.Sprintf("%.0f", *fn.InvocationsPerMinute)
		} else if fn.Invoker != nil {
			rate = fmt.Sprintf("%d total", fn.Invoker.Invocations)
		}
		o.printf("%s/%s\t%s\t%s\t%s\t%d MiB\t%s\n",
			fn.Project, fn.Service, fn.Module, describeTriggers(fn),
			rate, fn.MemoryBytes>>20, fn.Status)
	}
	if resp.InvokerDropped > 0 {
		o.printf("\n%d events were dropped by the invoker queue.\n", resp.InvokerDropped)
	}
	return o.Err()
}

// describeTriggers renders the trigger chips as text.
func describeTriggers(fn api.FunctionView) string {
	var parts []string
	if fn.HTTP {
		switch {
		case len(fn.Domains) > 0:
			parts = append(parts, "http "+fn.Domains[0])
		default:
			parts = append(parts, "http")
		}
	}
	for _, ev := range fn.Events {
		parts = append(parts, "event "+strings.Join(ev.On, ","))
	}
	for _, cr := range fn.Crons {
		parts = append(parts, "cron "+cr.Schedule)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " · ")
}

// invokerWaker forwards store-change wakes to the invoker.
func invokerWaker(ctx context.Context, ch <-chan struct{}, inv *functions.Invoker) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			inv.Wake()
		}
	}
}
