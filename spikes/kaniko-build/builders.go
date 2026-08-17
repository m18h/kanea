package main

import (
	"encoding/json"
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// buildReq is what Kanea's pipeline runner would hand a build driver.
type buildReq struct {
	Context string // host directory holding the Dockerfile
	Tag     string // full registry reference to push
	Cache   bool   // use/populate a remote layer cache
	OutDir  string // host directory the builder writes its digest file into
}

// builder is one candidate image-build driver, defined by exactly the command
// line Kanea would run as a short-lived containerd task.
type builder struct {
	Name   string
	Image  string
	Status string // upstream maintenance status: a first-class selection criterion

	// argv returns the process arguments inside the container.
	argv func(r buildReq) []string
	// env returns environment variables for the build process.
	env func(r buildReq) []string
	// mounts returns the bind mounts the builder needs.
	mounts func(r buildReq) []specs.Mount
	// digestFile is the host path (inside OutDir) where the image digest lands.
	digestFile func(r buildReq) string
	// parseDigest extracts the image digest from that file's contents.
	parseDigest func(raw string) string
	// cacheHit is the log marker proving a cached layer was reused.
	cacheHit string
	// notes explains the flags that are not self-evident.
	notes string
	// runAsRoot overrides the image's USER. BuildKit's rootless image otherwise
	// re-enters rootlesskit inside a container that already is a sandbox, and
	// newuidmap cannot acquire its file capabilities there.
	runAsRoot bool
	// defaultPriv is the privilege level this builder needs to work at all,
	// established by probing (see phaseHardening). Everything except buildkit
	// runs at containerd's default capability set.
	defaultPriv privilege
}

const (
	cacheRepo = regAddr + "/kanea/cache"
	ctxMount  = "/workspace"
	outMount  = "/out"
)

func roMount(src, dst string) specs.Mount {
	return specs.Mount{Destination: dst, Type: "bind", Source: src, Options: []string{"rbind", "ro"}}
}

func rwMount(src, dst string) specs.Mount {
	return specs.Mount{Destination: dst, Type: "bind", Source: src, Options: []string{"rbind", "rw"}}
}

var builders = []builder{
	{
		Name:        "kaniko",
		Image:       kanikoImage,
		defaultPriv: privDefault,
		Status:      "ARCHIVED upstream (read-only since 2025-06; last release v1.24.0, 2025-05-23)",
		notes:       "one-shot by design; --insecure for the plaintext spike registry",
		argv: func(r buildReq) []string {
			args := []string{"/kaniko/executor",
				"--context", "dir://" + ctxMount,
				"--dockerfile", ctxMount + "/Dockerfile",
				"--destination", r.Tag,
				"--digest-file", outMount + "/digest",
				"--insecure", "--skip-tls-verify",
				"--verbosity", "info",
			}
			if r.Cache {
				args = append(args, "--cache=true", "--cache-repo", cacheRepo, "--cache-copy-layers")
			}
			return args
		},
		env: func(r buildReq) []string {
			return []string{"DOCKER_CONFIG=/kaniko/.docker", "PATH=/usr/local/bin:/kaniko:/usr/bin:/bin"}
		},
		mounts: func(r buildReq) []specs.Mount {
			return []specs.Mount{
				roMount(r.Context, ctxMount),
				roMount(authDir+"/config.json", "/kaniko/.docker/config.json"),
				rwMount(r.OutDir, outMount),
			}
		},
		digestFile: func(r buildReq) string { return r.OutDir + "/digest" },
	},
	{
		Name:   "buildkit",
		Image:  buildkitImage,
		Status: "actively maintained (v0.32.0, 2026-07-29)",
		notes: "buildkitd is a daemon, not a one-shot task: as a containerd task it needs a PRIVILEGED " +
			"container (nested runc does bind mounts), uid 0, a host /sys/fs/cgroup, an existing " +
			"XDG_RUNTIME_DIR, and --oci-worker-net=host for the nested build steps",
		runAsRoot:   true,
		defaultPriv: privPrivileged,
		cacheHit:    "CACHED",
		argv: func(r buildReq) []string {
			out := fmt.Sprintf("type=image,name=%s,push=true,registry.insecure=true", r.Tag)
			args := []string{"buildctl-daemonless.sh", "build",
				"--frontend", "dockerfile.v0",
				"--local", "context=" + ctxMount,
				"--local", "dockerfile=" + ctxMount,
				"--output", out,
				"--metadata-file", outMount + "/metadata.json",
			}
			if r.Cache {
				args = append(args,
					"--export-cache", fmt.Sprintf("type=registry,ref=%s,mode=max,registry.insecure=true", cacheRepo),
					"--import-cache", fmt.Sprintf("type=registry,ref=%s,registry.insecure=true", cacheRepo),
				)
			}
			return args
		},
		env: func(r buildReq) []string {
			return []string{
				// --oci-worker-no-process-sandbox is refused unless buildkitd is
				// rootless, and rootlesskit cannot start inside a containerd task
				// ("newuidmap: Could not set caps"), so the worker runs as root
				// with host networking for the nested build steps.
				"BUILDKITD_FLAGS=--oci-worker-net=host",
				"DOCKER_CONFIG=/root/.docker",
				"HOME=/root",
				"XDG_RUNTIME_DIR=/tmp",
				"PATH=/usr/local/bin:/usr/bin:/bin",
			}
		},
		mounts: func(r buildReq) []specs.Mount {
			return []specs.Mount{
				roMount(r.Context, ctxMount),
				roMount(authDir+"/config.json", "/root/.docker/config.json"),
				rwMount(r.OutDir, outMount),
				// Nested runc needs a real cgroup hierarchy, else every RUN step
				// fails with "no cgroup mount found in mountinfo".
				rwMount("/sys/fs/cgroup", "/sys/fs/cgroup"),
			}
		},
		digestFile: func(r buildReq) string { return r.OutDir + "/metadata.json" },
		// buildctl writes a JSON metadata document, not a bare digest.
		parseDigest: func(raw string) string {
			var meta map[string]any
			if err := json.Unmarshal([]byte(raw), &meta); err != nil {
				return ""
			}
			d, _ := meta["containerimage.digest"].(string)
			return d
		},
	},
	{
		Name:        "buildah",
		Image:       buildahImage,
		defaultPriv: privDefault,
		Status:      "actively maintained (source v1.45.0, 2026-07-30; newest published image v1.43.1)",
		notes:       "--isolation chroot avoids nested user namespaces; vfs storage avoids /dev/fuse",
		argv: func(r buildReq) []string {
			layers := "--layers=false"
			cache := ""
			if r.Cache {
				layers = "--layers=true"
				cache = fmt.Sprintf(" --cache-to %s --cache-from %s", cacheRepo, cacheRepo)
			}
			// bud then push: buildah keeps them separate, unlike kaniko/buildkit.
			script := fmt.Sprintf(
				"set -e; buildah --storage-driver vfs bud --isolation chroot --tls-verify=false "+
					"--authfile /auth/config.json %s%s -t %s %s && "+
					"buildah --storage-driver vfs push --tls-verify=false --authfile /auth/config.json "+
					"--digestfile %s/digest %s",
				layers, cache, r.Tag, ctxMount, outMount, r.Tag)
			return []string{"/bin/sh", "-c", script}
		},
		env: func(r buildReq) []string {
			return []string{
				"STORAGE_DRIVER=vfs",
				"BUILDAH_ISOLATION=chroot",
				"PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
				"HOME=/root",
			}
		},
		mounts: func(r buildReq) []specs.Mount {
			return []specs.Mount{
				roMount(r.Context, ctxMount),
				roMount(authDir, "/auth"),
				rwMount(r.OutDir, outMount),
			}
		},
		digestFile: func(r buildReq) string { return r.OutDir + "/digest" },
	},
}
