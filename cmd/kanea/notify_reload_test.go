package main

import (
	"context"
	"testing"

	"github.com/m18h/kanea/internal/jobspec"
	"github.com/m18h/kanea/internal/notify"
	"github.com/m18h/kanea/internal/settings"
	"github.com/m18h/kanea/internal/store"
)

// Change-driven notification routes (PRD v1.46): the node-level defaults are
// built by the same RoutesFor projects use, with the scope cleared, and the
// reloader rebuilds only when the fingerprint over its actual inputs changes.

func TestNodeRoutesForClearsTheProjectScope(t *testing.T) {
	// "node" names the channels; it must never *scope* them. A route whose
	// Project were "node" would match only events of a project literally called
	// node: the node-wide default would silently see nothing.
	ctx := context.Background()
	n := &jobspec.Notifications{
		Webhook: &jobspec.WebhookChannel{URL: "http://127.0.0.1:9/hook"},
		On:      []string{"*"},
	}
	// Loopback over plain http needs both egress opt-outs; CheckURL runs at
	// build time, and a refused URL here would be testing the egress guard
	// rather than the scope.
	egress := notify.EgressPolicy{AllowPrivate: true, AllowHTTP: true}

	routes, err := nodeRoutesFor(ctx, n, egress, nil, nil)
	if err != nil {
		t.Fatalf("nodeRoutesFor: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("%d routes, want 1", len(routes))
	}
	if got := routes[0].Project; got != "" {
		t.Errorf("Project = %q, want empty; the dispatcher's \"sees everything\"", got)
	}
	if got := routes[0].Channel.Name(); got != "node/webhook" {
		t.Errorf("channel name = %q, want %q; the label survives the scope clearing", got, "node/webhook")
	}

	// A nil block is a node without defaults, not an error.
	if routes, err := nodeRoutesFor(ctx, nil, egress, nil, nil); err != nil || routes != nil {
		t.Errorf("nodeRoutesFor(nil) = %v routes, err %v; want nil, nil", routes, err)
	}
}

func TestNotifyFingerprintChangesOnlyWithConfig(t *testing.T) {
	// The reloader rebuilds channels only on a fingerprint change (the v1.44
	// Providers.Current rule): a rebuild per store write would put a
	// secrets-store read behind every deploy. So the fingerprint must ignore
	// everything that is not notification configuration.
	ctx := context.Background()
	st := openScalingStore(t)
	cfg := notifySettings{store: st}

	base, err := notifyFingerprint(ctx, cfg)
	if err != nil {
		t.Fatalf("notifyFingerprint: %v", err)
	}

	// An unrelated kv write: the kind every reconcile pass produces.
	if _, err := st.Apply(ctx, store.Mutation{
		Op: store.OpPut, Kind: store.KindKV, Key: "unrelated/key", Value: []byte(`"noise"`),
	}); err != nil {
		t.Fatalf("write unrelated value: %v", err)
	}
	same, err := notifyFingerprint(ctx, cfg)
	if err != nil {
		t.Fatalf("notifyFingerprint: %v", err)
	}
	if same != base {
		t.Fatal("the fingerprint moved on an unrelated store write; every deploy would rebuild the channels")
	}

	// The node record is one of the fingerprint's inputs.
	if err := settings.SaveNotifications(ctx, st, settings.NotificationSettings{
		Channels: &jobspec.Notifications{
			Webhook: &jobspec.WebhookChannel{URL: "https://example.com/hook"},
			On:      []string{"deploy.*"},
		},
	}); err != nil {
		t.Fatalf("SaveNotifications: %v", err)
	}
	changed, err := notifyFingerprint(ctx, cfg)
	if err != nil {
		t.Fatalf("notifyFingerprint: %v", err)
	}
	if changed == base {
		t.Fatal("the fingerprint did not move when the node channels changed; the reload would never fire")
	}
}
