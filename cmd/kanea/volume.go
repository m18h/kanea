package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/m18h/kanea/internal/api"
	"github.com/m18h/kanea/internal/storage"
)

// runVolume is `kanea volume list` (PRD v1.69, §16.2).
//
// The nesting is the point. A storage resource is the thing an operator
// configured; the mounts under it are what is actually using it, which is the
// question being asked when a disk fills up. A flat list would repeat an NFS
// export's address once per service and still not say they were the same one.
func runVolume(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: kanea volume list [--json]")
	}
	fs := flag.NewFlagSet("volume list", flag.ContinueOnError)
	socket := socketFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	client := api.NewClient(*socket)
	resp, err := client.Volumes(context.Background())
	if err != nil {
		return err
	}
	o := newOut()
	if *asJSON {
		body, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return err
		}
		o.println(string(body))
		return o.Err()
	}
	if len(resp.Storages) == 0 {
		o.println("No volumes.")
		return o.Err()
	}

	o.table()
	o.println("STORAGE / MOUNT\tTYPE\tUSED\tSIZE\tSTATE\tPATH")
	for _, st := range resp.Storages {
		o.printf("%s\t%s\t\t\t\t%s\n",
			st.Project+"/"+st.Name, st.Type, st.Target)
		for i, m := range st.Mounts {
			o.printf("  %s %s/%s %s\t%s\t%s\t%s\t%s\t%s\n",
				branch(i, len(st.Mounts)), m.Project, m.Service, m.Volume,
				st.Type, bytesOrGap(m.UsedBytes), bytesOrGap(m.SizeBytes),
				mountStateLabel(m), m.Path)
		}
	}
	o.endTable()
	if unmeasured(resp) {
		o.println("\nUSED is blank where nothing has been measured yet: a volume is " +
			"sampled in the background, and s3 volumes are never walked.")
	}
	return o.Err()
}

// branch renders the tree connector, so a storage resource's mounts read as
// belonging to it rather than as more rows.
func branch(i, n int) string {
	if i == n-1 {
		return "└─"
	}
	return "├─"
}

// bytesOrGap renders a size, or a gap when there is none.
//
// A gap, never a zero: an unmeasured volume and an empty one are different
// facts, and "0 B" says the second (§9.2). Likewise a volume with no declared
// budget has no size to show: it is not a budget of nothing.
func bytesOrGap(n *int64) string {
	if n == nil {
		return "-"
	}
	return storage.HumanBytes(*n)
}

// mountStateLabel names the state, spelling out the one that needs it.
func mountStateLabel(m api.VolumeMount) string {
	if m.State == api.MountOver && m.SizeBytes != nil && m.UsedBytes != nil {
		// Deliberately not "full" or "failed": a budget is not a quota (R31),
		// the volume is still serving, and the word has to say so.
		return "over budget"
	}
	return m.State
}

// unmeasured reports whether anything is missing a reading, so the note that
// explains why appears only when there is something to explain.
func unmeasured(resp api.VolumesResponse) bool {
	for _, st := range resp.Storages {
		for _, m := range st.Mounts {
			if m.UsedBytes == nil {
				return true
			}
		}
	}
	return false
}
