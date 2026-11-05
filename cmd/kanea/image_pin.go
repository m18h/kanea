package main

import (
	"context"

	"github.com/m18h/kanea/internal/autoupdate"
	"github.com/m18h/kanea/internal/reconciler"
)

// imagePinner implements api.ImagePinner over the image watcher's own resolve
// (PRD v1.114), so an apply that changes the declared tag of an auto-updating
// service lands as one rolling deploy instead of one onto the bare tag and a
// second onto the digest the watcher pins a tick later.
//
// A wiring adapter and nothing else: the resolve, the credential lookup and
// the canonical `name@sha256:...` form all live in internal/autoupdate, with
// one caller each side, because a tag resolved two ways is two spec hashes.
type imagePinner struct {
	resolver autoupdate.Resolver
	secrets  autoupdate.Secrets
}

func (p imagePinner) ResolvePin(ctx context.Context, d reconciler.Desired) (string, error) {
	return autoupdate.ResolvePin(ctx, p.resolver, p.secrets, d)
}
