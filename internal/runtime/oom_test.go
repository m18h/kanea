package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCgroup lays out a fake alloc cgroup at the path readOOMState composes,
// so the tests exercise the real path arithmetic rather than a stand-in.
func writeCgroup(t *testing.T, root, allocID string, files map[string]string) {
	t.Helper()
	dir := root + CgroupPath(WorkloadSlice, allocID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadOOMStateReadsTheKillCounter(t *testing.T) {
	tests := []struct {
		name       string
		events     string
		memoryMax  string
		wantKilled bool
		wantLimit  uint64
	}{
		{
			name:       "killed with a declared limit",
			events:     "low 0\nhigh 0\nmax 12\noom 3\noom_kill 1\n",
			memoryMax:  "268435456\n",
			wantKilled: true,
			wantLimit:  268435456,
		},
		{
			// The v1.58 default: no resources block, so the kill came from the
			// workload parent's collective ceiling and the message must say so.
			name:       "killed with no declared limit",
			events:     "oom 1\noom_kill 2\n",
			memoryMax:  "max\n",
			wantKilled: true,
			wantLimit:  0,
		},
		{
			// `oom` counts allocation failures, `oom_kill` counts kills. A
			// process that hit its ceiling and handled it was not killed.
			name:       "allocation pressure without a kill",
			events:     "oom 5\noom_kill 0\n",
			memoryMax:  "268435456\n",
			wantKilled: false,
			wantLimit:  268435456,
		},
		{
			name:       "kernel that does not report oom_kill",
			events:     "low 0\nhigh 0\nmax 0\n",
			memoryMax:  "max\n",
			wantKilled: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeCgroup(t, root, "shop-web-0", map[string]string{
				"memory.events": tc.events,
				"memory.max":    tc.memoryMax,
			})

			got := readOOMState(root, "shop-web-0")
			if !got.Known {
				t.Fatal("Known = false for a readable cgroup")
			}
			if got.Killed != tc.wantKilled {
				t.Errorf("Killed = %v, want %v", got.Killed, tc.wantKilled)
			}
			if got.MemoryLimit != tc.wantLimit {
				t.Errorf("MemoryLimit = %d, want %d", got.MemoryLimit, tc.wantLimit)
			}
		})
	}
}

// An unreadable cgroup is not evidence of anything. This is the case that
// decides whether a `kanea stop` gets reported as a memory problem: the exit is
// 137 either way, and only the cgroup can tell them apart — so when it cannot
// be read, nothing may be claimed.
func TestAnUnreadableCgroupClaimsNothing(t *testing.T) {
	root := t.TempDir()

	got := readOOMState(root, "shop-web-0")
	if got.Known {
		t.Error("Known = true for a cgroup that does not exist")
	}
	if got.Killed {
		t.Error("Killed = true with no cgroup to have read it from")
	}
}

// memory.events without memory.max still answers the question it was asked.
func TestAMissingMemoryMaxReadsAsUnbounded(t *testing.T) {
	root := t.TempDir()
	writeCgroup(t, root, "shop-web-0", map[string]string{
		"memory.events": "oom_kill 1\n",
	})

	got := readOOMState(root, "shop-web-0")
	if !got.Known || !got.Killed {
		t.Fatalf("readOOMState = %+v, want a known kill", got)
	}
	if got.MemoryLimit != 0 {
		t.Errorf("MemoryLimit = %d, want 0 (unbounded)", got.MemoryLimit)
	}
}

func TestCgroupCounterIgnoresMalformedLines(t *testing.T) {
	content := "\n  \nnot-a-pair\noom_kill notanumber\n"
	if got := cgroupCounter(content, "oom_kill"); got != 0 {
		t.Errorf("cgroupCounter = %d, want 0", got)
	}
	if got := cgroupCounter("oom_kill 7\n", "oom_kill"); got != 7 {
		t.Errorf("cgroupCounter = %d, want 7", got)
	}
}
