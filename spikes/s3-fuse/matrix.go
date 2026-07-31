package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"
)

// runMatrix establishes what a workload can actually DO on each mount. The
// drivers differ enough that this table, not throughput, is the deciding input:
// a volume that cannot rename or append breaks ordinary applications
// (databases, log rotation, atomic-write-then-rename config reloads).
func runMatrix(ctx context.Context, d *driver) error {
	fmt.Printf("\n── %s: POSIX semantics (%s) ──\n", d.Name, d.notes)
	if err := resetBucket(); err != nil {
		return err
	}

	base := d.path("matrix")
	if err := os.MkdirAll(base, 0o755); err != nil {
		capability(d.Name, "mkdir", false, err.Error())
	} else {
		capability(d.Name, "mkdir", true, "")
	}

	// --- create + read back ---
	payload := make([]byte, 256<<10)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	file := base + "/data.bin"
	err := os.WriteFile(file, payload, 0o644)
	readBack, rerr := os.ReadFile(file)
	ok := err == nil && rerr == nil && bytes.Equal(payload, readBack)
	capability(d.Name, "write+read", ok, detailOf(err, rerr))
	check(d.Name+": sequential write then read back (256 KiB)", ok, detailOf(err, rerr))

	// --- stat ---
	fi, serr := os.Stat(file)
	statOK := serr == nil && fi.Size() == int64(len(payload))
	capability(d.Name, "stat size", statOK, detailOf(serr, nil))

	// --- append: log files, and anything that opens O_APPEND ---
	f, aerr := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0o644)
	if aerr == nil {
		_, aerr = f.Write([]byte("appended"))
		if cerr := f.Close(); aerr == nil {
			aerr = cerr
		}
	}
	appended, _ := os.ReadFile(file)
	appendOK := aerr == nil && len(appended) == len(payload)+8
	capability(d.Name, "append", appendOK, detailOf(aerr, nil))

	// --- in-place overwrite (seek + write): databases, anything mmap-ish ---
	f, werr := os.OpenFile(file, os.O_WRONLY, 0o644)
	if werr == nil {
		_, werr = f.WriteAt([]byte("MIDDLE"), 1024)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
	}
	mid, _ := os.ReadFile(file)
	overwriteOK := werr == nil && len(mid) > 1030 && string(mid[1024:1030]) == "MIDDLE"
	capability(d.Name, "write at offset", overwriteOK, detailOf(werr, nil))

	// --- truncate --- (re-stat with a settle window: some drivers report the old
	// size briefly from an attribute cache, which is not the same as failing)
	terr := os.Truncate(file, 4096)
	var size int64 = -1
	deadlineT := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadlineT) {
		if fi, err := os.Stat(file); err == nil {
			size = fi.Size()
			if size == 4096 {
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	truncOK := terr == nil && size == 4096
	truncDetail := detailOf(terr, nil)
	if terr == nil && !truncOK {
		truncDetail = fmt.Sprintf("no error but size stayed %d", size)
	}
	capability(d.Name, "truncate", truncOK, truncDetail)

	// --- rename: the atomic-config-swap pattern Kanea itself relies on ---
	rerr2 := os.Rename(file, base+"/renamed.bin")
	capability(d.Name, "rename", rerr2 == nil, detailOf(rerr2, nil))

	// --- symlink ---
	lerr := os.Symlink(base+"/renamed.bin", base+"/link.bin")
	capability(d.Name, "symlink", lerr == nil, detailOf(lerr, nil))

	// --- chmod ---
	cerr := os.Chmod(base+"/renamed.bin", 0o600)
	capability(d.Name, "chmod", cerr == nil, detailOf(cerr, nil))

	// --- delete + rmdir ---
	derr := os.Remove(base + "/renamed.bin")
	capability(d.Name, "delete", derr == nil, detailOf(derr, nil))

	// --- visibility of objects written out of band (another node, or `mc`) ---
	tmp, terr2 := os.CreateTemp("", "kanea-spike-oob-*")
	if terr2 != nil {
		return terr2
	}
	_, _ = tmp.WriteString("out-of-band\n")
	_ = tmp.Close()
	defer os.Remove(tmp.Name())
	if _, err := mc("cp", tmp.Name(), fmt.Sprintf("kaneaspike/%s/matrix/oob.txt", bucket)); err != nil {
		return err
	}
	var oobOK bool
	var oobDetail string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(base + "/oob.txt")
		if err == nil && strings.TrimSpace(string(b)) == "out-of-band" {
			oobOK = true
			oobDetail = fmt.Sprintf("visible after %.1fs", 20-time.Until(deadline).Seconds())
			break
		}
		oobDetail = detailOf(err, nil)
		time.Sleep(500 * time.Millisecond)
	}
	capability(d.Name, "sees other writers", oobOK, oobDetail)
	check(d.Name+": object written out of band becomes visible", oobOK, oobDetail)

	return nil
}

func detailOf(errs ...error) string {
	var parts []string
	for _, e := range errs {
		if e != nil {
			parts = append(parts, trimErr(e))
		}
	}
	return strings.Join(parts, "; ")
}

func trimErr(e error) string {
	s := e.Error()
	// Errors carry the full mount path; the driver name already says which mount.
	for _, d := range drivers {
		s = strings.ReplaceAll(s, d.Mount+"/", "")
	}
	if len(s) > 70 {
		s = s[:70] + "…"
	}
	return s
}
