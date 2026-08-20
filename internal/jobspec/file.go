package jobspec

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/m18h/kanea/internal/secrets"
)

// Mounted files (PRD §6.2 R35).

// Byte budgets (PRD §21). These are the first size bounds the platform has for
// a Desired record, and they exist because R35 is the first rule that can put
// bulk bytes in one.
//
// The per-file number is MaxSecretBytes', deliberately: it is already this
// codebase's word for "large enough for a real credential or config, small
// enough to catch a mistake", and nobody should have to learn a second number.
//
// The per-service number is set by replication rather than taste. A record is
// JSON in bbolt, so content base64s at 1.33x; the change log holds a *second
// full copy* of every value it ships; and §15.3 batches segments by count, not
// by size. 128 KiB of content is therefore ~170 KiB in the record, ~340 KiB of
// bbolt writes per apply and ~230 KiB uploaded, forever, per service.
const (
	MaxFileBytes        = 64 << 10
	MaxServiceFileBytes = 128 << 10
	MaxSpecFileBytes    = 512 << 10
)

// DefaultFileMode is what a plain file gets when the spec declares none: the
// mode resolv.conf uses, for the reason it states. The file is bind-mounted
// into a container that may run as any uid and it holds nothing secret, so
// owner-only would break a workload for no gain.
const DefaultFileMode = "0644"

// DefaultSecretFileMode is what a file carrying a secret reference gets: the
// secrets tree's mode, owner-only, chowned to the reading container.
const DefaultSecretFileMode = "0400"

// validateFiles enforces R35 over one service's file blocks.
//
// It builds the mount-path namespace itself rather than sharing
// validatePassthrough's: that one hangs off validateTask, which returns early
// for a task-less service, and a rule that silently stops running for some
// inputs is worse than one that never existed. Volumes and sockets are the
// other two things that can occupy a path, and two things on one path means
// one of them silently wins, whichever kind they are.
func validateFiles(svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	if len(svc.Files) == 0 {
		return diags
	}

	seenPath := map[string]hcl.Range{}
	for _, v := range svc.Volumes {
		if _, dup := seenPath[v.MountPath]; !dup {
			seenPath[v.MountPath] = v.DefRange
		}
	}
	if svc.Task != nil {
		for _, sock := range svc.Task.Sockets {
			if _, dup := seenPath[sock.MountPath]; !dup {
				seenPath[sock.MountPath] = sock.DefRange
			}
		}
	}

	seenName := map[string]hcl.Range{}
	total := 0

	for _, f := range svc.Files {
		diags = append(diags, validateName("File", f.Name, f.DefRange)...)

		if prev, dup := seenName[f.Name]; dup {
			diags = append(diags, fileDiag(f, "Duplicate file",
				fmt.Sprintf("Service %q declares file %q at %s already.", svc.Name, f.Name, prev)))
		}
		seenName[f.Name] = f.DefRange

		diags = append(diags, validateFilePath(svc, f, seenPath)...)
		diags = append(diags, validateFileMode(svc, f)...)

		if err := CheckFileSize(f.Name, len(f.Content)); err != nil {
			diags = append(diags, fileDiag(f, "File is too large",
				fmt.Sprintf("Service %q: %s", svc.Name, err)))
		}
		authored := secrets.StripPlaceholders(f.Content, f.Nonce, len(f.SecretRefs))
		if err := checkNoNUL(authored, fmt.Sprintf("file %q", f.Name)); err != nil {
			diags = append(diags, fileDiag(f, "Invalid file content",
				fmt.Sprintf("Service %q: %s", svc.Name, err)))
		}
		total += len(f.Content)
	}

	if total > MaxServiceFileBytes {
		diags = append(diags, fileDiag(svc.Files[0], "Service file content is too large",
			fmt.Sprintf("Service %q declares %d bytes of file content; the limit is %d. "+
				"A service record is replicated in full on every deploy (§21).",
				svc.Name, total, MaxServiceFileBytes)))
	}
	return diags
}

// validateFilePath applies the same rules a volume's mount path gets, plus the
// collision check against everything else that mounts.
func validateFilePath(svc *Service, f *File, seenPath map[string]hcl.Range) hcl.Diagnostics {
	p := f.Path
	bad := func(detail string) hcl.Diagnostics {
		return hcl.Diagnostics{fileDiag(f, "Invalid file path",
			fmt.Sprintf("File %q of service %q %s", f.Name, svc.Name, detail))}
	}

	switch {
	case p == "":
		return bad("declares no path.")
	case !filepath.IsAbs(p):
		return bad(fmt.Sprintf("mounts at %q; the path must be absolute.", p))
	case filepath.Clean(p) != p:
		return bad(fmt.Sprintf("mounts at %q; the path must be clean (no %q, %q or trailing slash).",
			p, "..", "."))
	case p == "/":
		return bad("mounts at /, which would replace the root filesystem.")
	}
	if sys := systemPathFor(p); sys != "" {
		return bad(fmt.Sprintf("mounts at %q, which is under %s. That is the kernel's, not the "+
			"workload's, and a file there would shadow it.", p, sys))
	}
	if p == "/etc/resolv.conf" {
		return bad("mounts at /etc/resolv.conf, which Kanea writes so the alloc can resolve " +
			"its peers by name (§5.2.5). Shadowing it would take the service off the internal zone.")
	}
	if prev, dup := seenPath[p]; dup {
		return bad(fmt.Sprintf("mounts at %q, which is already mounted at %s. Two things on one "+
			"path means one of them silently wins.", p, prev))
	}
	seenPath[p] = f.DefRange
	return nil
}

// validateFileMode enforces the permission rules.
//
// An execute bit is refused outright: a `file` block delivers configuration and
// not a program, which is what lets the bind carry noexec unconditionally
// rather than depending on the mode. And a plain file that is not
// world-readable is refused with the reason, because a file only its owner may
// read is a secret and there is a mechanism for those.
func validateFileMode(svc *Service, f *File) hcl.Diagnostics {
	if f.Mode == "" {
		return nil
	}
	bad := func(detail string) hcl.Diagnostics {
		return hcl.Diagnostics{fileDiag(f, "Invalid file mode",
			fmt.Sprintf("File %q of service %q %s", f.Name, svc.Name, detail))}
	}
	mode, err := strconv.ParseUint(f.Mode, 8, 32)
	if err != nil || len(f.Mode) > 4 {
		return bad(fmt.Sprintf("declares mode %q; it must be octal, e.g. %q.",
			f.Mode, DefaultFileMode))
	}
	if mode&0o111 != 0 {
		return bad(fmt.Sprintf("declares mode %q, which is executable. A file block delivers "+
			"configuration, not a program, and the mount carries noexec.", f.Mode))
	}
	if mode&0o7000 != 0 {
		return bad(fmt.Sprintf("declares mode %q; setuid, setgid and sticky bits are refused.", f.Mode))
	}
	if len(f.SecretRefs) == 0 && mode&0o004 == 0 {
		return bad(fmt.Sprintf("declares mode %q, which only its owner may read, but interpolates "+
			"no secret. A file that has to be owner-only is a secret: use ${secret.<scope>.<name>} "+
			"in its content and Kanea will place it 0400 on a tmpfs.", f.Mode))
	}
	if len(f.SecretRefs) > 0 && mode&0o077 != 0 {
		return bad(fmt.Sprintf("declares mode %q while interpolating a secret; a file carrying one "+
			"may not be group- or world-readable. Omit mode for %s.", f.Mode, DefaultSecretFileMode))
	}
	return nil
}

// CheckFileSize is the shared core of the parse-time and apply-time size rules.
func CheckFileSize(name string, n int) error {
	if n > MaxFileBytes {
		return fmt.Errorf("file %q is %d bytes; the limit is %d (PRD §21)", name, n, MaxFileBytes)
	}
	return nil
}

// CheckFileContent is the apply seam's half of the content rules: the byte
// budget and the NUL refusal that makes a secret placeholder inexpressible by
// an author. It exists because at that seam content arrives base64-encoded,
// where a NUL is perfectly expressible.
func CheckFileContent(name string, content []byte, nonce string, refs int) error {
	if err := CheckFileSize(name, len(content)); err != nil {
		return err
	}
	return checkNoNUL(secrets.StripPlaceholders(content, nonce, refs), fmt.Sprintf("file %q", name))
}

// CheckFilePath is the apply seam's half of validateFilePath.
func CheckFilePath(name, p string) error {
	switch {
	case p == "":
		return fmt.Errorf("file %q declares no path", name)
	case !filepath.IsAbs(p):
		return fmt.Errorf("file %q mounts at %q; the path must be absolute", name, p)
	case filepath.Clean(p) != p:
		return fmt.Errorf("file %q mounts at %q; the path must be clean", name, p)
	case p == "/":
		return fmt.Errorf("file %q mounts at /", name)
	}
	if sys := systemPathFor(p); sys != "" {
		return fmt.Errorf("file %q mounts at %q, which is under %s", name, p, sys)
	}
	if p == "/etc/resolv.conf" {
		return fmt.Errorf("file %q mounts at /etc/resolv.conf, which Kanea writes", name)
	}
	return nil
}

// validateSource enforces the shape rules on a `source` and returns the form
// the reader should use.
//
// It cleans rather than refusing an unclean path, because "./config.yaml" is
// how anyone naturally writes this and is what the PRD's own example shows.
// What is refused is what actually matters: an absolute path, and any `..`
// component - refused rather than cleaned away, because `a/../../b` cleans to
// something outside the directory and silently accepting that is the whole
// hazard. Containment is asserted again by the reader, at the point of use,
// because these checks are lexical and a symlink is not.
func validateSource(name, src string) (string, error) {
	if src == "" {
		return "", fmt.Errorf("file %q sets an empty source", name)
	}
	if filepath.IsAbs(src) {
		return "", fmt.Errorf("file %q sets source = %q; it must be relative to the spec that "+
			"declares it", name, src)
	}
	if strings.Contains(src, `\`) {
		return "", fmt.Errorf("file %q sets source = %q; use forward slashes", name, src)
	}
	for _, part := range strings.Split(src, "/") {
		if part == ".." {
			return "", fmt.Errorf("file %q sets source = %q; it may not leave the spec's "+
				"directory", name, src)
		}
	}
	clean := filepath.Clean(src)
	if clean == "." || clean == "/" {
		return "", fmt.Errorf("file %q sets source = %q, which names no file", name, src)
	}
	return clean, nil
}

func fileDiag(f *File, summary, detail string) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  summary,
		Detail:   detail,
		Subject:  f.DefRange.Ptr(),
	}
}

// resolveFileSources reads every `source` through Options.Files (R35).
//
// The reader is a seam and not an os.ReadFile for a reason worth restating
// where someone might be tempted to simplify it: a spec is parsed in three
// places and only one of them has a directory beside it. The GitOps sync reads
// blobs out of a commit tree with no working tree; the dashboard's spec editor
// and MCP parse an in-memory string *inside kanead, as root*. A parser that
// opened files itself would make POST /v1/spec/render an arbitrary file read as
// root for any signed-in user, embedded into a record they could read back.
//
// So a caller with no root supplies nil, and `source` is refused there by name.
func resolveFileSources(spec *Spec, opts Options) hcl.Diagnostics {
	var diags hcl.Diagnostics

	for _, svc := range spec.Services {
		for _, f := range svc.Files {
			if f.Source == "" {
				continue
			}
			clean, err := validateSource(f.Name, f.Source)
			if err != nil {
				diags = append(diags, fileDiag(f, "Invalid file source",
					fmt.Sprintf("Service %q: %s.", svc.Name, err)))
				continue
			}
			if opts.Files == nil {
				diags = append(diags, fileDiag(f, "File source is not available here",
					fmt.Sprintf("File %q of service %q sets source = %q, but this spec is parsed "+
						"without a directory beside it (the dashboard's editor and the MCP tools "+
						"parse text, not files). Use content instead.",
						f.Name, svc.Name, f.Source)))
				continue
			}
			body, err := opts.Files.ReadSpecFile(f.DefRange.Filename, clean)
			if err != nil {
				diags = append(diags, fileDiag(f, "Cannot read file source",
					fmt.Sprintf("File %q of service %q: %s.", f.Name, svc.Name, err)))
				continue
			}
			f.Content = body
		}
	}
	return diags
}

// validateSpecFileBudget bounds one apply's total file content.
//
// It exists because handleApply decodes through a 1 MiB io.LimitReader, and an
// oversized body there produces an *opaque JSON decode error* rather than a
// refusal naming the file. This is the courtesy check that puts the message in
// front of whoever typed it; the apply seam carries the real one, because
// GitOps reaches the Store without passing through the CLI.
func validateSpecFileBudget(spec *Spec) hcl.Diagnostics {
	total := 0
	for _, svc := range spec.Services {
		for _, f := range svc.Files {
			total += len(f.Content)
		}
	}
	if total <= MaxSpecFileBytes {
		return nil
	}
	return hcl.Diagnostics{{
		Severity: hcl.DiagError,
		Summary:  "Too much file content in one apply",
		Detail: fmt.Sprintf("This spec declares %d bytes of file content across every service; "+
			"the limit is %d (PRD §21). An apply is one request, and one request is bounded.",
			total, MaxSpecFileBytes),
	}}
}

// validateFileDeclaration refuses the two ways a file block can be malformed
// before anything tries to render it: no content at all, or both forms.
func validateFileDeclaration(svc *Service, raw *hclService) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for i, f := range svc.Files {
		if i >= len(raw.Files) {
			break
		}
		hasContent := raw.Files[i].Content != nil && !exprIsNull(raw.Files[i].Content)
		switch {
		case hasContent && f.Source != "":
			diags = append(diags, fileDiag(f, "File declares content and source",
				fmt.Sprintf("File %q of service %q sets both; they are two ways to say the "+
					"same thing, so exactly one is required.", f.Name, svc.Name)))
		case !hasContent && f.Source == "":
			diags = append(diags, fileDiag(f, "File has no content",
				fmt.Sprintf("File %q of service %q must set content or source.", f.Name, svc.Name)))
		}
	}
	return diags
}

// exprIsNull reports whether an expression is absent in practice: gohcl leaves
// an unset optional hcl.Expression as a literal null rather than nil.
func exprIsNull(expr hcl.Expression) bool {
	val, diags := expr.Value(nil)
	return !diags.HasErrors() && val.IsNull()
}

// CheckFileMode is the apply seam's half of validateFileMode.
func CheckFileMode(name, spelled string, hasSecrets bool) error {
	if spelled == "" {
		return nil
	}
	mode, err := strconv.ParseUint(spelled, 8, 32)
	if err != nil || len(spelled) > 4 {
		return fmt.Errorf("file %q declares mode %q; it must be octal", name, spelled)
	}
	switch {
	case mode&0o111 != 0:
		return fmt.Errorf("file %q declares mode %q, which is executable; the mount carries noexec",
			name, spelled)
	case mode&0o7000 != 0:
		return fmt.Errorf("file %q declares mode %q; setuid, setgid and sticky bits are refused",
			name, spelled)
	case !hasSecrets && mode&0o004 == 0:
		return fmt.Errorf("file %q declares mode %q, which only its owner may read, but "+
			"interpolates no secret", name, spelled)
	case hasSecrets && mode&0o077 != 0:
		return fmt.Errorf("file %q declares mode %q while interpolating a secret; it may not be "+
			"group- or world-readable", name, spelled)
	}
	return nil
}
