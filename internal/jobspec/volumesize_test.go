package jobspec_test

// `size` and `create` (PRD v1.69, §6.2 R31 / R15).

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
	"github.com/m18h/kanea/internal/jobspec"
)

func parseVolumeSpec(t *testing.T, storageBlock, volumeBody string) hcl.Diagnostics {
	t.Helper()
	src := "spec_version = 1\nproject \"shop\" {}\n" + storageBlock + `
service "web" {
  project = "shop"
  task "app" { image = "nginx" }
  volume "d" {
    storage    = "vol"
    mount_path = "/d"
` + volumeBody + `
  }
}
`
	_, diags := jobspec.ParseSource(jobspec.Options{}, "shop.hcl", []byte(src))
	return diags
}

const localStorage = `storage "vol" { type = "local" }`

func TestAVolumeSizeParses(t *testing.T) {
	for _, size := range []string{`"10GiB"`, `"512MiB"`, `"1TiB"`, `"1048576"`} {
		t.Run(size, func(t *testing.T) {
			if diags := parseVolumeSpec(t, localStorage, "    size = "+size); diags.HasErrors() {
				t.Errorf("size = %s was refused: %s", size, jobspec.FormatDiagnostics(diags))
			}
		})
	}
}

func TestAnInvalidVolumeSizeIsRefusedWithItsPosition(t *testing.T) {
	for _, tc := range []struct {
		size string
		want string
	}{
		{`"ten gigabytes"`, "byte count"},
		{`"0GiB"`, "positive"},
		{`"-5GiB"`, "positive"},
		{`""`, "byte count"},
	} {
		t.Run(tc.size, func(t *testing.T) {
			diags := parseVolumeSpec(t, localStorage, "    size = "+tc.size)
			if !diags.HasErrors() {
				t.Fatal("expected a refusal, got none")
			}
			out := jobspec.FormatDiagnostics(diags)
			if !strings.Contains(out, tc.want) {
				t.Errorf("diagnostics = %q, want %q", out, tc.want)
			}
			// The position, not just the complaint: this is a spec someone is
			// editing, and the line is the useful half.
			if !strings.Contains(out, "shop.hcl:") {
				t.Errorf("diagnostics = %q, want a file and line", out)
			}
		})
	}
}

// R31's refusal. s3 is not walked, so a budget on it could never be evaluated:
// and a control the platform silently drops is worse than one nobody claimed
// (R21's rule).
func TestASizeOnAnS3VolumeIsRefused(t *testing.T) {
	s3 := "storage \"vol\" {\n  type   = \"s3\"\n  bucket = \"media\"\n}"

	diags := parseVolumeSpec(t, s3, `    size = "10GiB"`)
	if !diags.HasErrors() {
		t.Fatal("expected a refusal, got none")
	}
	out := jobspec.FormatDiagnostics(diags)
	if !strings.Contains(out, "cannot be given a size") {
		t.Errorf("diagnostics = %q, want the refusal to name the field", out)
	}
	// It must also say what size actually means here, or the reader will
	// assume they lost a quota they never had.
	if !strings.Contains(out, "budget") {
		t.Errorf("diagnostics = %q, want it to say a size is a budget", out)
	}
}

// Everything that *is* walked takes a budget, including host and nfs: those
// refuse ownership (R24) and this is a different question.
func TestASizeIsAcceptedOnEveryWalkedDriver(t *testing.T) {
	for name, block := range map[string]string{
		"local": localStorage,
		"host":  "storage \"vol\" {\n  type = \"host\"\n  path = \"/srv/media\"\n}",
		"nfs":   "storage \"vol\" {\n  type   = \"nfs\"\n  server = \"10.0.0.5\"\n  export = \"/tank\"\n}",
		"smb":   "storage \"vol\" {\n  type   = \"smb\"\n  server = \"10.0.0.5\"\n  share  = \"media\"\n}",
	} {
		t.Run(name, func(t *testing.T) {
			if diags := parseVolumeSpec(t, block, `    size = "10GiB"`); diags.HasErrors() {
				t.Errorf("size on %s was refused: %s", name, jobspec.FormatDiagnostics(diags))
			}
		})
	}
}

// --- create (R15) ---

func TestCreateIsAcceptedOnAHostStorage(t *testing.T) {
	block := "storage \"vol\" {\n  type   = \"host\"\n  path   = \"/srv/media\"\n  create = true\n}"
	if diags := parseVolumeSpec(t, block, ""); diags.HasErrors() {
		t.Errorf("create on a host storage was refused: %s", jobspec.FormatDiagnostics(diags))
	}
}

// It is host-only because it is the only driver where the question arises. On
// the others it would be a spec that means something other than what it says.
func TestCreateIsRefusedOnEveryOtherDriver(t *testing.T) {
	for name, block := range map[string]string{
		"local": "storage \"vol\" {\n  type   = \"local\"\n  create = true\n}",
		"nfs":   "storage \"vol\" {\n  type   = \"nfs\"\n  server = \"10.0.0.5\"\n  export = \"/t\"\n  create = true\n}",
		"smb":   "storage \"vol\" {\n  type   = \"smb\"\n  server = \"10.0.0.5\"\n  share  = \"m\"\n  create = true\n}",
		"s3":    "storage \"vol\" {\n  type   = \"s3\"\n  bucket = \"media\"\n  create = true\n}",
	} {
		t.Run(name, func(t *testing.T) {
			diags := parseVolumeSpec(t, block, "")
			if !diags.HasErrors() {
				t.Fatalf("create on %s was accepted", name)
			}
			out := jobspec.FormatDiagnostics(diags)
			if !strings.Contains(out, "create is not valid") {
				t.Errorf("diagnostics = %q, want the refusal to name create", out)
			}
		})
	}
}

// The default has not moved. A host storage that says nothing about creation
// still means "this directory already exists", which is R15's whole point.
func TestAHostStorageWithoutCreateIsUnchanged(t *testing.T) {
	block := "storage \"vol\" {\n  type = \"host\"\n  path = \"/srv/media\"\n}"
	if diags := parseVolumeSpec(t, block, ""); diags.HasErrors() {
		t.Errorf("a plain host storage was refused: %s", jobspec.FormatDiagnostics(diags))
	}
}
