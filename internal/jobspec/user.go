package jobspec

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// Who a workload runs as (R23) and who owns its data (R24).
//
// The two rules are one story and are implemented together. Each is inert
// alone: a non-root user with no writable volume cannot start, and a volume
// owned by a uid nothing runs as is decoration. Together they are what lets a
// stock image start with no capabilities at all — the CHOWN/SETUID/SETGID trio
// R13 grants exists so an image can do at startup what these state up front.

// resolveVolumeOwnership fills each volume's undeclared ownership from its
// task's user (R24).
//
// This is defaulting, not policy, and it is resolved at parse time for that
// reason: unlike R20's TLS mode it does not depend on which machine the spec
// lands on, so resolving it here is what lets `kanea plan` show the ownership
// that will actually be applied.
//
// It is also the difference between the feature working and not. A spec that
// sets task.user and forgets the volume gets a permission denial at startup —
// precisely the failure R23/R24 exist to remove — and requiring both would put
// the same two numbers in every spec for no decision anybody makes twice.
//
// **Inheritance stops at a driver that cannot carry ownership.** A `host` or
// `nfs` volume that *declares* uid, gid or mode is refused, but one that merely
// sits in a service whose task named a user is left alone. The distinction is
// the whole reason this runs over the spec rather than over one service: a
// default that turned into a hard error would mean adding `user` to a task
// broke every NFS volume it happened to have, and there would be no way to
// say "not that one". The task's user block is a statement about the process,
// not a claim about what an NFS server does with its files.
func resolveVolumeOwnership(spec *Spec) {
	for _, svc := range spec.Services {
		for _, v := range svc.Volumes {
			// An unknown storage is already a diagnostic; inheriting into it
			// would only add a second error about the same typo.
			st := spec.StorageByName(v.Storage)
			if st == nil {
				continue
			}
			if _, refused := ownershipRefusedBy[st.Type]; refused {
				continue
			}
			if svc.Task != nil && svc.Task.User != nil {
				if v.UID == nil {
					uid := svc.Task.User.UID
					v.UID = &uid
				}
				if v.GID == nil {
					gid := svc.Task.User.GID
					v.GID = &gid
				}
			}
			// A volume that ends up owned — inherited or declared — takes the
			// default mode if it named none.
			if v.Owned() {
				applyDefaultMode(v)
			}
		}
	}
}

// applyDefaultMode gives an owned volume a mode if it declared none.
func applyDefaultMode(v *Volume) {
	if v.Mode != nil {
		return
	}
	mode := fmt.Sprintf("%04o", DefaultVolumeMode)
	v.Mode = &mode
}

// validateUser enforces R23.
//
// Shape and range only. There is nothing else to check: the block names no
// path, no grant and no host resource, so unlike R15 and R17 there is no
// second, node-side half of this rule. A uid is just a number, and whether the
// image has a user by that number is the image's business — a spec that names
// one the image does not know still runs, which is the point of numeric IDs.
func validateUser(svc *Service) hcl.Diagnostics {
	u := svc.Task.User
	if u == nil {
		return nil
	}
	var diags hcl.Diagnostics

	diags = append(diags, checkID(svc, "uid", u.UID, u.DefRange)...)
	diags = append(diags, checkID(svc, "gid", u.GID, u.DefRange)...)

	if len(u.Groups) > MaxGroups {
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Too many supplementary groups",
			Detail: fmt.Sprintf("Task %q of service %q names %d supplementary groups; at most %d "+
				"are allowed. Every one of them is copied into the OCI spec of every alloc.",
				svc.Task.Name, svc.Name, len(u.Groups), MaxGroups),
			Subject: u.DefRange.Ptr(),
		})
	}
	seen := map[int]bool{}
	for _, g := range u.Groups {
		diags = append(diags, checkID(svc, "group", g, u.DefRange)...)
		if seen[g] {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate supplementary group",
				Detail: fmt.Sprintf("Task %q of service %q names group %d more than once.",
					svc.Task.Name, svc.Name, g),
				Subject: u.DefRange.Ptr(),
			})
		}
		seen[g] = true
	}
	return diags
}

// checkID bounds one uid, gid or supplementary group.
func checkID(svc *Service, what string, id int, rng hcl.Range) hcl.Diagnostics {
	switch {
	case id < 0:
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid " + what,
			Detail: fmt.Sprintf("Task %q of service %q declares %s %d; it must not be negative.",
				svc.Task.Name, svc.Name, what, id),
			Subject: rng.Ptr(),
		}}
	case id > MaxID:
		return hcl.Diagnostics{{
			Severity: hcl.DiagError,
			Summary:  "Invalid " + what,
			Detail: fmt.Sprintf("Task %q of service %q declares %s %d; the largest allowed is %d. "+
				"%d is (uid_t)-1, which the kernel reserves to mean \"unchanged\".",
				svc.Task.Name, svc.Name, what, id, MaxID, MaxID+1),
			Subject: rng.Ptr(),
		}}
	}
	return nil
}

// validateVolumeOwnership enforces the half of R24 that is a refusal.
//
// A driver that cannot carry ownership is a `plan` error, not a field quietly
// dropped on the way to the mount command. That is R21's rule about a control
// the layer below discards, applied to storage: a spec claiming a volume is
// owned by 999 when nothing will make it so is worse than one that never said.
func validateVolumeOwnership(spec *Spec, svc *Service, v *Volume) hcl.Diagnostics {
	if !v.Owned() {
		return nil
	}
	var diags hcl.Diagnostics

	if v.Mode != nil {
		if _, err := ParseMode(*v.Mode); err != nil {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid volume mode",
				Detail: fmt.Sprintf("Volume %q of service %q: %s. Write it as octal digits in a "+
					"string, e.g. mode = \"0700\" — HCL has no octal literal, so an unquoted 0700 "+
					"would be read as decimal.", v.Name, svc.Name, err),
				Subject: v.DefRange.Ptr(),
			})
		}
	}
	if v.UID != nil {
		diags = append(diags, checkVolumeID(svc, v, "uid", *v.UID)...)
	}
	if v.GID != nil {
		diags = append(diags, checkVolumeID(svc, v, "gid", *v.GID)...)
	}

	// Whether the driver can honour it. An unknown storage name is already a
	// diagnostic from validateVolumes; saying nothing more here keeps one typo
	// to one error.
	st := spec.StorageByName(v.Storage)
	if st == nil {
		return diags
	}
	if why, refused := ownershipRefusedBy[st.Type]; refused {
		// Reaching here means the spec wrote it: resolveVolumeOwnership does
		// not inherit into a driver that cannot carry ownership, so this is
		// never an error about a field the author did not type.
		diags = append(diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Storage driver cannot own a volume",
			Detail: fmt.Sprintf("Volume %q of service %q is backed by storage %q of type %q, "+
				"which cannot be given a uid, gid or mode: %s. Remove them here and set the "+
				"ownership where that driver decides it.",
				v.Name, svc.Name, v.Storage, st.Type, why),
			Subject: v.DefRange.Ptr(),
		})
	}
	return diags
}

// ownershipRefusedBy names the drivers that cannot carry ownership, and why.
//
// Both refusals are structural rather than unimplemented. A host directory is
// the operator's — R15 says Kanea never creates it and never deletes it, and
// chowning it is the same trespass under a smaller name. And the kernel NFS
// client has no uid= option at all: ownership is decided by the server and
// idmapd, so a field here would be a claim made at the layer least able to
// detect that it was false.
var ownershipRefusedBy = map[string]string{
	StorageHost: "a host volume is a directory the operator already owns, and Kanea neither " +
		"creates it nor changes it (R15). Set the ownership on the node, outside Kanea",
	StorageNFS: "the kernel NFS client has no uid= or gid= mount option — ownership is the NFS " +
		"server's to decide, through its export options and idmapd",
}

// checkVolumeID bounds a uid or gid written on a volume.
func checkVolumeID(svc *Service, v *Volume, what string, id int) hcl.Diagnostics {
	if id >= 0 && id <= MaxID {
		return nil
	}
	return hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Invalid volume " + what,
		Detail: fmt.Sprintf("Volume %q of service %q declares %s %d; it must be between 0 and %d.",
			v.Name, svc.Name, what, id, MaxID),
		Subject: v.DefRange.Ptr(),
	}}
}
