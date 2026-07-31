package logging_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanea-dev/kanea/internal/logging"
)

func TestNewZeroConfig(t *testing.T) {
	log, closer, err := logging.New(logging.Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Close() //nolint:errcheck
	log.Info("hello", "component", "test")
}

func TestNewInvalidLevel(t *testing.T) {
	if _, _, err := logging.New(logging.Config{Level: "chatty"}); err == nil {
		t.Fatal("want error for unknown level")
	}
	if _, _, err := logging.New(logging.Config{Format: "xml"}); err == nil {
		t.Fatal("want error for unknown format")
	}
}

func TestFileSinkJSONAndLevels(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "kanead.log")
	log, closer, err := logging.New(logging.Config{File: file, Format: "json", Level: "info"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Close() //nolint:errcheck

	log.Debug("hidden") // below level
	log.Info("deployed", "project", "shop", "service", "web")

	lines := readLines(t, file)
	if len(lines) != 1 {
		t.Fatalf("want 1 line (debug suppressed), got %d: %v", len(lines), lines)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	for k, want := range map[string]string{"msg": "deployed", "level": "INFO", "project": "shop", "service": "web"} {
		if rec[k] != want {
			t.Errorf("key %s: want %q, got %v", k, want, rec[k])
		}
	}
}

func TestFileSinkText(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "edge.log")
	log, closer, err := logging.New(logging.Config{File: file, Format: "text", Level: "debug"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Close() //nolint:errcheck

	log.Debug("listening", "addr", ":443")
	out := strings.Join(readLines(t, file), "\n")
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, `msg=listening`) || !strings.Contains(out, `addr=:443`) {
		t.Errorf("unexpected text output: %s", out)
	}
}

func TestRotation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "kanead.log")
	log, closer, err := logging.New(logging.Config{File: file, MaxSizeMB: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer closer.Close() //nolint:errcheck

	payload := strings.Repeat("x", 900) // ~1 KB per record
	for i := 0; i < 1500; i++ {         // ~1.5 MB total > 1 MiB cap
		log.Info("tick", "n", i, "payload", payload)
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) < 2 {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Fatalf("want rotation (current + >=1 backup), got %v", names)
	}
	cur, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Size() > 1<<20 {
		t.Errorf("current file exceeds MaxSizeMB=1: %d bytes", cur.Size())
	}
}

func TestNop(_ *testing.T) {
	logging.Nop().Info("nowhere", "k", "v")
}

func readLines(t *testing.T, file string) []string {
	t.Helper()
	f, err := os.Open(file) //nolint:gosec // test-local path
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}
