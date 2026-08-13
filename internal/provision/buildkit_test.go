package provision

import (
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/m18h/kanea/internal/gitops"
)

// The unit's --addr and BuildkitSocket must name the same socket: doctor and
// kanead dial what BuildkitSocket says, the daemon binds what the unit says,
// and when the two disagreed every provisioned node's builds dialed a path
// nothing creates while doctor warned about a healthy daemon.
func TestTheUnitListensWhereBuildkitSocketPoints(t *testing.T) {
	l := testLayout(t)
	if !strings.Contains(l.buildkitUnit(), "--addr "+BuildkitSocket(l)+" ") {
		t.Errorf("the buildkit unit does not listen on %s", BuildkitSocket(l))
	}
}

// gitops.DefaultBuildkitSocket is the deliberate duplicate (the
// ownershipRefusedBy pattern): gitops must not import provision, so the
// default is restated there and pinned here. Drift is the bug this fixes —
// the constant once predated the installer and named a socket under /run.
func TestTheDefaultSocketIsTheProvisionedDaemons(t *testing.T) {
	if got, want := gitops.DefaultBuildkitSocket, BuildkitSocket(DefaultLayout()); got != want {
		t.Errorf("gitops.DefaultBuildkitSocket = %s, but the provisioned daemon listens on %s", got, want)
	}
}

// The data directory is created 0750 root:root by `kanea init` and kanead,
// and the daemon's home lives under it: without the group grant every path
// beneath answers EACCES, which buildkitd reports as a fatal "permission
// denied" for an optional config file that does not exist.
func TestEnsureTraversalGrantsTheGroupExactlyOneBit(t *testing.T) {
	gid := os.Getgid()
	for _, tc := range []struct {
		name string
		mode os.FileMode
		want os.FileMode
	}{
		{"a closed 0700 gains group execute", 0o700, 0o710},
		{"an init-style 0750 is left as it is", 0o750, 0o750},
		{"a permissive 0755 is not tightened", 0o755, 0o755},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			// Twice: SetupBuildkit runs on every `kanea install`, and the
			// second pass must find nothing left to change.
			for range 2 {
				if err := ensureTraversal(dir, gid); err != nil {
					t.Fatal(err)
				}
			}
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != tc.want {
				t.Errorf("mode = %o, want %o", got, tc.want)
			}
			if st, ok := info.Sys().(*syscall.Stat_t); !ok {
				t.Fatal("no Stat_t on this platform")
			} else if int(st.Gid) != gid {
				t.Errorf("gid = %d, want %d", st.Gid, gid)
			}
		})
	}
}
