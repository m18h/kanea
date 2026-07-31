package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

func outDirFor(b *builder, phase string) string {
	return fmt.Sprintf("%s/out/%s-%s", workDir, b.Name, phase)
}

func tagFor(b *builder, phase string) string {
	return fmt.Sprintf("%s/kanea/%s-%s:v1", regAddr, b.Name, phase)
}

// phaseBuild — the core question: build a Dockerfile as a containerd task and
// push it to an authenticated registry, with no Docker daemon anywhere.
func phaseBuild(ctx context.Context, e *env, b *builder) error {
	fmt.Printf("\n── %s: build + push as a containerd task ──\n", b.Name)
	info(b.Name+" upstream status", b.Status)

	req := buildReq{Context: ctxDir, Tag: tagFor(b, "build"), OutDir: outDirFor(b, "build")}
	var res runResult
	dur, err := timed(b.Name+" build+push", func() error {
		var rerr error
		res, rerr = runBuilder(ctx, e, b, req, runOpts{priv: b.defaultPriv})
		if rerr != nil {
			return rerr
		}
		if res.exitCode != 0 {
			return fmt.Errorf("exit %d: %s", res.exitCode, tailLog(res.logs, 6))
		}
		return nil
	})
	check(fmt.Sprintf("%s: builds and pushes as a containerd task (%s)", b.Name, b.defaultPriv),
		err == nil, fmt.Sprintf("%v", dur))
	if err != nil {
		return nil // keep evaluating the other builders
	}

	digest, derr := registryDigest(ctx, req.Tag)
	check(b.Name+": image is retrievable from the registry", derr == nil && digest != "",
		fmt.Sprintf("%s -> %s", req.Tag, digest))

	// PRD §10.2: "the deploy pins the produced digest", so the runner must be
	// able to read the digest back out of the build.
	raw, rerr := os.ReadFile(b.digestFile(req))
	reported := strings.TrimSpace(string(raw))
	if b.parseDigest != nil {
		reported = b.parseDigest(reported)
	}
	hasDigest := rerr == nil && strings.HasPrefix(reported, "sha256:")
	detail := reported
	if hasDigest && digest != "" && reported != digest {
		detail += " (differs from the registry digest — index vs manifest)"
	}
	check(b.Name+": reports the produced image digest, pinnable by the deploy",
		hasDigest, detail)

	return nil
}

// phaseCache — PRD §10.2 requires layer caching via a cache repo.
func phaseCache(ctx context.Context, e *env, b *builder) error {
	fmt.Printf("\n── %s: layer cache ──\n", b.Name)

	req := buildReq{Context: ctxDir, Tag: tagFor(b, "cache"), Cache: true, OutDir: outDirFor(b, "cache")}

	var cold, warm time.Duration
	var res runResult
	var err error
	cold, err = timed(b.Name+" cold build (populates cache)", func() error {
		res, err = runBuilder(ctx, e, b, req, runOpts{priv: b.defaultPriv})
		if err != nil {
			return err
		}
		if res.exitCode != 0 {
			return fmt.Errorf("exit %d: %s", res.exitCode, tailLog(res.logs, 6))
		}
		return nil
	})
	if err != nil {
		check(b.Name+": cache-enabled build succeeds", false, err.Error())
		return nil
	}

	req.Tag = tagFor(b, "cache2")
	req.OutDir = outDirFor(b, "cache2")
	warm, err = timed(b.Name+" warm build (should hit cache)", func() error {
		res, err = runBuilder(ctx, e, b, req, runOpts{priv: b.defaultPriv})
		if err != nil {
			return err
		}
		if res.exitCode != 0 {
			return fmt.Errorf("exit %d: %s", res.exitCode, tailLog(res.logs, 6))
		}
		return nil
	})
	if err != nil {
		check(b.Name+": warm build succeeds", false, err.Error())
		return nil
	}

	// Assert on cache *hits*, not on wall clock: kaniko demonstrably reuses
	// cached layers yet gains no time on a small build, because its cost is
	// dominated by snapshotting the filesystem rather than by the RUN steps.
	hit := strings.Contains(res.logs, b.cacheHit)
	speedup := float64(cold) / float64(warm)
	check(b.Name+": warm build reuses cached layers", hit,
		fmt.Sprintf("marker %q; cold %v -> warm %v (%.1fx)", b.cacheHit,
			cold.Round(time.Millisecond), warm.Round(time.Millisecond), speedup))

	tags, _ := registryTags(ctx, "kanea/cache")
	info(b.Name+" cache repo state", tailLog(tags, 1))
	return nil
}

// phaseHardening — how much privilege does each builder actually need? Kanea's
// workload default is drop-ALL-caps + no-new-privileges (AGENTS.md #6); a
// builder that needs more is a documented exception, and one that needs
// `privileged` is a security regression the PRD would have to justify.
func phaseHardening(ctx context.Context, e *env, b *builder) error {
	fmt.Printf("\n── %s: minimum privilege ──\n", b.Name)

	levels := []privilege{privHardened, privDefault, privPrivileged}
	minimum := ""
	for _, p := range levels {
		req := buildReq{
			Context: ctxDir,
			Tag:     fmt.Sprintf("%s/kanea/%s-priv%d:v1", regAddr, b.Name, int(p)),
			OutDir:  fmt.Sprintf("%s/out/%s-priv%d", workDir, b.Name, int(p)),
		}
		res, err := runBuilder(ctx, e, b, req, runOpts{priv: p})
		ok := err == nil && res.exitCode == 0
		detail := ""
		if !ok {
			if err != nil {
				detail = err.Error()
			} else {
				detail = fmt.Sprintf("exit %d: %s", res.exitCode, tailLog(res.logs, 3))
			}
		}
		fmt.Printf("  %-9s %-38s %s\n", map[bool]string{true: "works", false: "fails"}[ok], p, detail)
		if ok && minimum == "" {
			minimum = p.String()
			break
		}
	}
	check(b.Name+": runs without a privileged container", minimum != "" && minimum != privPrivileged.String(),
		"minimum: "+orNone(minimum))
	return nil
}

// phaseLimits — PRD §10.2: builds run under cgroup CPU/memory caps so they
// cannot starve workloads.
func phaseLimits(ctx context.Context, e *env, b *builder) error {
	fmt.Printf("\n── %s: under build isolation limits ──\n", b.Name)

	req := buildReq{Context: ctxDir, Tag: tagFor(b, "limited"), OutDir: outDirFor(b, "limited")}
	opts := runOpts{
		priv:     b.defaultPriv,
		memLimit: 1 << 30,    // 1 GiB
		cpuQuota: 2 * 100000, // 2 CPUs
		cgroup:   "/kanea-workloads.slice/kanea-build-" + b.Name,
	}
	var res runResult
	dur, err := timed(b.Name+" build under 1 GiB / 2 CPU", func() error {
		var rerr error
		res, rerr = runBuilder(ctx, e, b, req, opts)
		if rerr != nil {
			return rerr
		}
		if res.exitCode != 0 {
			return fmt.Errorf("exit %d (137 = OOM-killed): %s", res.exitCode, tailLog(res.logs, 4))
		}
		return nil
	})
	check(b.Name+": builds under cgroup memory/CPU caps", err == nil,
		fmt.Sprintf("%v in %s", dur, opts.cgroup))
	return nil
}

// phaseFailure — PRD §10.2/§22 R4 require build failures to surface clearly:
// non-zero exit plus logs a user can act on.
func phaseFailure(ctx context.Context, e *env, b *builder) error {
	fmt.Printf("\n── %s: failing build surfaces cleanly ──\n", b.Name)

	req := buildReq{Context: badDir, Tag: tagFor(b, "bad"), OutDir: outDirFor(b, "bad")}
	res, err := runBuilder(ctx, e, b, req, runOpts{priv: b.defaultPriv})
	if err != nil {
		check(b.Name+": failing build exits non-zero", false, err.Error())
		return nil
	}
	check(b.Name+": failing build exits non-zero", res.exitCode != 0,
		fmt.Sprintf("exit %d", res.exitCode))

	// The log must name the failing step or its exit status, not just "error".
	lower := strings.ToLower(res.logs)
	useful := strings.Contains(lower, "17") || strings.Contains(lower, "exit code") ||
		strings.Contains(lower, "did not complete successfully")
	check(b.Name+": failure log identifies the failing step", useful, tailLog(res.logs, 3))

	digest, derr := registryDigest(ctx, req.Tag)
	check(b.Name+": nothing is pushed on failure", derr != nil || digest == "",
		fmt.Sprintf("registry lookup: %v", firstNonEmpty(errString(derr), digest)))
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none — even privileged failed"
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "(empty)"
}
