package main

import (
	"context"
	"fmt"
	"os"
	"time"
)

// runFailure answers the reliability half of the spike question: when the object
// store goes away, does the mount fail fast or hang forever, and does it recover
// when the store comes back? A mount that hangs uninterruptibly takes the
// workload's threads with it — and, if Kanea ever stats it from the reconciler,
// the control plane too. That is the property that disqualifies a driver.
func runFailure(ctx context.Context, d *driver) error {
	fmt.Printf("\n── %s: object store outage ──\n", d.Name)
	if err := resetBucket(); err != nil {
		return err
	}

	file := d.path("outage.txt")
	if err := os.WriteFile(file, []byte("before-outage\n"), 0o644); err != nil {
		check(d.Name+": seed before outage", false, trimErr(err))
		return nil
	}
	// Remount so reads must actually reach the store rather than a warm cache.
	if err := d.unmount(); err != nil {
		return err
	}
	if err := d.mount(); err != nil {
		return err
	}

	if err := systemctl("stop", minioUnit); err != nil {
		return err
	}
	restarted := false
	defer func() {
		if !restarted {
			_ = systemctl("start", minioUnit)
		}
	}()

	// --- read with the store down ---
	readDone := make(chan result, 1)
	go func() {
		t0 := time.Now()
		_, err := os.ReadFile(file)
		readDone <- result{err: err, dur: time.Since(t0)}
	}()

	var detail string
	var failedFast bool
	select {
	case r := <-readDone:
		failedFast = true
		outcome := "returned an error"
		if r.err == nil {
			outcome = "served from cache"
		}
		detail = fmt.Sprintf("%s after %v: %s", outcome, r.dur.Round(time.Millisecond), trimErrOrNil(r.err))
	case <-time.After(blockCap):
		detail = fmt.Sprintf("still blocked after %v — caller is stuck in the FUSE call", blockCap)
	}
	check(d.Name+": read during outage returns instead of hanging", failedFast, detail)

	// --- write with the store down ---
	writeDone := make(chan result, 1)
	go func() {
		t0 := time.Now()
		err := os.WriteFile(d.path("during-outage.txt"), []byte("x"), 0o644)
		writeDone <- result{err: err, dur: time.Since(t0)}
	}()
	var writeDetail string
	var writeReturned bool
	select {
	case r := <-writeDone:
		writeReturned = true
		outcome := "error"
		if r.err == nil {
			outcome = "accepted (buffered locally — data not yet durable)"
		}
		writeDetail = fmt.Sprintf("%s after %v: %s", outcome, r.dur.Round(time.Millisecond), trimErrOrNil(r.err))
	case <-time.After(blockCap):
		writeDetail = fmt.Sprintf("still blocked after %v", blockCap)
	}
	check(d.Name+": write during outage returns instead of hanging", writeReturned, writeDetail)

	// --- recovery: same mount, no remount ---
	if err := systemctl("start", minioUnit); err != nil {
		return err
	}
	restarted = true
	waitMinio()

	var recovered bool
	var recDetail string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(file)
		if err == nil && len(b) > 0 {
			recovered = true
			recDetail = "same mount, no remount needed"
			break
		}
		recDetail = trimErrOrNil(err)
		time.Sleep(time.Second)
	}
	if !recovered {
		// Distinguish a wedged/stale mount from actual data loss: ask the store.
		if out, err := mc("stat", fmt.Sprintf("kaneaspike/%s/outage.txt", bucket)); err == nil && len(out) > 0 {
			recDetail += " — but the object IS in the bucket (mount is stale, data intact)"
		} else {
			recDetail += " — and the object is NOT in the bucket (data lost)"
		}
	}
	check(d.Name+": mount recovers when the store returns", recovered, recDetail)

	return nil
}

// blockCap bounds how long the spike waits for a blocked FUSE call. It is
// deliberately long: the question is not "is it slow" but "does the caller ever
// get control back", and a workload thread stuck here is unkillable.
const blockCap = 120 * time.Second

type result struct {
	err error
	dur time.Duration
}

func trimErrOrNil(err error) string {
	if err == nil {
		return "no error"
	}
	return trimErr(err)
}

func waitMinio() {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if out, err := mc("ls", "kaneaspike/"+bucket); err == nil {
			_ = out
			return
		}
		time.Sleep(time.Second)
	}
}
