package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"
)

// memhog is a controllable test workload for the cgroup checks: it allocates and
// touches anonymous memory and/or reads a file into page cache, then sleeps.
// File-based rendezvous (-ready/-go/-done) lets the parent move the process into
// the target cgroup BEFORE any allocation, so all charges land correctly.
func runMemhog(args []string) error {
	fs := flag.NewFlagSet("memhog", flag.ContinueOnError)
	anon := fs.String("anon", "0", "anonymous memory to allocate+touch (e.g. 600M)")
	file := fs.String("file", "", "file to read fully into page cache")
	oomAdj := fs.Int("oom-adj", 0, "value for /proc/self/oom_score_adj")
	ready := fs.String("ready", "", "touch this file once started (pre-allocation)")
	goF := fs.String("go", "", "wait for this file before allocating")
	done := fs.String("done", "", "touch this file once allocation is complete")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *oomAdj != 0 {
		if err := os.WriteFile("/proc/self/oom_score_adj", []byte(fmt.Sprint(*oomAdj)), 0o644); err != nil {
			return fmt.Errorf("oom_score_adj: %w", err)
		}
	}
	if *ready != "" {
		touch(*ready)
	}
	if *goF != "" && !waitFile(*goF, 60_000_000_000) { // 60s
		return fmt.Errorf("go file never appeared")
	}

	var buf []byte
	if n, _ := parseSize(*anon); n > 0 {
		buf = make([]byte, n)
		for i := 0; i < len(buf); i += 4096 { // fault in every page
			buf[i] = 1
		}
	}
	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(io.Discard, f); err != nil { // page cache charged to our memcg
			return err
		}
	}
	if *done != "" {
		touch(*done)
	}
	fmt.Printf("memhog pid=%d anon=%s file=%s: allocated, sleeping\n", os.Getpid(), *anon, *file)
	runtime.KeepAlive(buf)
	for { // NOT select{}; the Go deadlock detector would kill us
		time.Sleep(time.Hour)
	}
}
