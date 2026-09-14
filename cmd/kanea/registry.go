package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/m18h/kanea/internal/gitops"
	"github.com/m18h/kanea/internal/registry"
	"github.com/m18h/kanea/internal/store"
)

// The internal build registry's wiring (PRD §5.2.14).
//
// Constraint 15's territory: an optional daemon dependency that is invisible
// in dev and fatal on a real node when it is not wired. registry_wiring_test.go
// reads this file and agent.go to pin that the registry built here actually
// reaches both halves of the pipeline stack.

// resolveRegistryDir resolves the registry's storage root under the data
// directory. No explicit override exists yet; the helper is the same shape as
// resolveBuildLogDir so one appears in exactly one place if it ever does.
func resolveRegistryDir(dataDir string) string {
	return filepath.Join(dataDir, "registry")
}

// buildRegistry assembles the internal registry, or nothing.
//
// Nil is a supported configuration (`--registry off`), and `--buildkit off`
// implies it: the registry exists for builds, and a node that cannot build
// has no reason to hold a listener open. The second return is the seam the
// pipeline stack consumes; zero when the registry is off, which is what makes
// an omitted build.target a refusal there.
func buildRegistry(
	addr, buildkit, dataDir string, st store.Store, logger *slog.Logger,
) (*registry.Registry, gitops.InternalRegistry, error) {
	if addr == "off" || buildkit == "off" {
		logger.Info("internal registry disabled",
			"detail", "an omitted build.target is refused on this node")
		return nil, gitops.InternalRegistry{}, nil
	}

	reg, err := registry.New(registry.Config{
		Addr: addr,
		Dir:  resolveRegistryDir(dataDir),
		// The rule-9 bound: a pushed repository must be a declared
		// <project>/<service> build pipeline. One bounded Store read per
		// write request, against the same record the sync loop polls.
		Allowed: func(ctx context.Context, project, service string) bool {
			cfg, _, err := store.GetValue[gitops.Config](ctx, st, store.KindProject, project)
			if err != nil {
				return false
			}
			_, ok := cfg.Builds[service]
			return ok
		},
		Logger: logger,
	})
	if err != nil {
		return nil, gitops.InternalRegistry{}, err
	}
	return reg, gitops.InternalRegistry{Addr: reg.Addr(), PushAuth: reg.PushDockerConfig}, nil
}
