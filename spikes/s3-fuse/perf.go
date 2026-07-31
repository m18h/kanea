package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	bigFileSize  = 128 << 20 // 128 MiB sequential test
	smallFiles   = 200
	smallFileLen = 4 << 10
)

// runPerf measures the two shapes that matter for Kanea volumes: streaming a
// large object (backups, media) and metadata churn (config dirs, small state).
//
// Numbers are against a LOCAL MinIO on loopback, so they measure *driver
// overhead*, not S3 round-trip time. Against real S3 every metadata operation
// additionally pays ~10-30 ms RTT, which widens the small-file gaps below.
func runPerf(ctx context.Context, d *driver) error {
	fmt.Printf("\n── %s: throughput and metadata ──\n", d.Name)
	if err := resetBucket(); err != nil {
		return err
	}
	dir := d.path("perf")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("%s: mkdir perf: %w", d.Name, err)
	}

	// --- sequential write ---
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	big := dir + "/big.bin"
	t0 := time.Now()
	f, err := os.Create(big)
	if err != nil {
		check(d.Name+": sequential write 128 MiB", false, trimErr(err))
		return nil
	}
	var werr error
	for written := 0; written < bigFileSize; written += len(chunk) {
		if _, werr = f.Write(chunk); werr != nil {
			break
		}
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr // close is where an S3 driver actually uploads
	}
	writeDur := time.Since(t0)
	check(d.Name+": sequential write 128 MiB", werr == nil,
		fmt.Sprintf("%s in %v", mib(bigFileSize, writeDur), writeDur.Round(time.Millisecond)))

	// --- time to durable: is the object in the bucket when close() returns? ---
	// A driver that uploads asynchronously means a workload can write, close,
	// exit successfully, and lose data if the alloc stops right after.
	durT0 := time.Now()
	durable, durDetail := false, "not in the bucket after 60s"
	for time.Since(durT0) < 60*time.Second {
		if out, err := mc("stat", fmt.Sprintf("kaneaspike/%s/perf/big.bin", bucket)); err == nil &&
			strings.Contains(out, "Size") {
			durable = true
			lag := time.Since(durT0)
			if lag < 500*time.Millisecond {
				durDetail = fmt.Sprintf("already durable when close() returned (+%v)", lag.Round(time.Millisecond))
			} else {
				durDetail = fmt.Sprintf("durable %v AFTER close() returned", lag.Round(time.Millisecond))
			}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	check(d.Name+": object durable in the bucket after close()", durable, durDetail)

	// Remount so the read is not served from the page/VFS cache we just filled.
	if err := d.unmount(); err != nil {
		return err
	}
	if err := d.mount(); err != nil {
		return err
	}

	// --- sequential read ---
	t0 = time.Now()
	rf, rerr := os.Open(big)
	var n int64
	if rerr == nil {
		n, rerr = io.Copy(io.Discard, rf)
		_ = rf.Close()
	}
	readDur := time.Since(t0)
	check(d.Name+": sequential read 128 MiB (cold mount)", rerr == nil && n == bigFileSize,
		fmt.Sprintf("%s in %v", mib(n, readDur), readDur.Round(time.Millisecond)))

	// --- metadata: create / list / stat / delete many small files ---
	small := make([]byte, smallFileLen)
	sdir := dir + "/many"
	if err := os.MkdirAll(sdir, 0o755); err != nil {
		return fmt.Errorf("%s: mkdir many: %w", d.Name, err)
	}
	t0 = time.Now()
	var cerr error
	for i := 0; i < smallFiles; i++ {
		if cerr = os.WriteFile(fmt.Sprintf("%s/f%03d", sdir, i), small, 0o644); cerr != nil {
			break
		}
	}
	createDur := time.Since(t0)
	check(fmt.Sprintf("%s: create %d small files", d.Name, smallFiles), cerr == nil,
		fmt.Sprintf("%v total, %.1f ms/file", createDur.Round(time.Millisecond),
			float64(createDur.Milliseconds())/smallFiles))

	t0 = time.Now()
	entries, lerr := os.ReadDir(sdir)
	listDur := time.Since(t0)
	check(fmt.Sprintf("%s: list %d entries", d.Name, smallFiles),
		lerr == nil && len(entries) == smallFiles,
		fmt.Sprintf("%d entries in %v", len(entries), listDur.Round(time.Millisecond)))

	t0 = time.Now()
	var serr error
	for i := 0; i < smallFiles; i++ {
		if _, serr = os.Stat(fmt.Sprintf("%s/f%03d", sdir, i)); serr != nil {
			break
		}
	}
	statDur := time.Since(t0)
	check(fmt.Sprintf("%s: stat %d files", d.Name, smallFiles), serr == nil,
		fmt.Sprintf("%v total, %.2f ms/stat", statDur.Round(time.Millisecond),
			float64(statDur.Microseconds())/1000/smallFiles))

	t0 = time.Now()
	var derr error
	for i := 0; i < smallFiles; i++ {
		if derr = os.Remove(fmt.Sprintf("%s/f%03d", sdir, i)); derr != nil {
			break
		}
	}
	delDur := time.Since(t0)
	check(fmt.Sprintf("%s: delete %d small files", d.Name, smallFiles), derr == nil,
		fmt.Sprintf("%v total", delDur.Round(time.Millisecond)))

	return nil
}
