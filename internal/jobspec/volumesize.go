package jobspec

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
)

// The R31 refusals (PRD v1.69).
//
// A budget only means something if it can be compared against a measurement,
// so a driver that cannot be measured cannot carry one. Refusing at `plan` is
// R21's rule: a `size` that reached a driver which quietly ignored it would be
// a control the spec claimed and the platform dropped.

// sizeRefusedBy names the drivers a volume budget cannot be declared on, and
// why. It is deliberately the ownershipRefusedBy shape, and deliberately
// separate from it: the two refusals have different memberships — a host volume
// takes a budget perfectly well (it is a directory on this node) and cannot
// take ownership, while s3 is the reverse.
var sizeRefusedBy = map[string]string{
	StorageS3: "an s3 volume is a FUSE mount over an object store, where measuring usage means " +
		"listing the bucket — one request per directory, on a schedule, to produce a number " +
		"the object store already bills you for. Kanea does not walk it, so a budget on it " +
		"could never be evaluated",
}

// validateVolumeSize enforces R31: a declared budget must be on a driver whose
// usage Kanea actually samples.
func validateVolumeSize(spec *Spec, svc *Service, v *Volume) hcl.Diagnostics {
	if v.SizeBytes == 0 {
		return nil // not declared; never defaulted (R11's rule)
	}

	// An unknown storage name is already a diagnostic from validateVolumes.
	// Saying nothing more keeps one typo to one error.
	st := spec.StorageByName(v.Storage)
	if st == nil {
		return nil
	}
	why, refused := sizeRefusedBy[st.Type]
	if !refused {
		return nil
	}
	return hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Storage driver cannot carry a volume budget",
		Detail: fmt.Sprintf("Volume %q of service %q is backed by storage %q of type %q, which "+
			"cannot be given a size: %s. Remove it — and note that size is a budget Kanea "+
			"reports and notifies on, never a quota it enforces (R31).",
			v.Name, svc.Name, v.Storage, st.Type, why),
		Subject: v.DefRange.Ptr(),
	}}
}

// validateStorageCreate enforces the R15 half of v1.69: `create` is a host-only
// flag, because it is the only driver where the question arises.
//
// A `local` directory is always created by the reconciler, so the flag would be
// a no-op that reads as meaningful; on `nfs`, `smb` and `s3` the directory is
// the remote's and Kanea could not create it if it tried. Each of those is a
// spec that means something other than what it says.
func validateStorageCreate(st *Storage) hcl.Diagnostics {
	if !st.Create || st.Type == StorageHost {
		return nil
	}
	detail := fmt.Sprintf("Storage %q is type %q and sets create = true, which only applies to "+
		"type %q.", st.Name, st.Type, StorageHost)
	switch st.Type {
	case StorageLocal:
		detail += " A local volume's directory is always created under the node's volume root," +
			" so there is nothing to opt into."
	case StorageNFS, StorageSMB, StorageS3:
		detail += " The directory belongs to the remote, and Kanea does not create it there."
	}
	return hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "create is not valid on this storage type",
		Detail:   detail,
		Subject:  st.DefRange.Ptr(),
	}}
}
