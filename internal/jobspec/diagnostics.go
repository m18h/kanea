package jobspec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
)

// ParseDuration parses the duration strings used across the spec ("10s", "2m").
// It rejects negatives and bare numbers, which time.ParseDuration would accept
// or silently misread ("10" is not 10 seconds, it is an error worth reporting).
func ParseDuration(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, errors.New(strings.TrimPrefix(err.Error(), "time: "))
	}
	if d < 0 {
		return 0, fmt.Errorf("must not be negative")
	}
	return d, nil
}

// FormatDiagnostics renders diagnostics for a terminal, one per line, with
// file:line:column. The CLI writes the result to stderr; it never prints
// diagnostics itself, so the format stays in one place.
//
// Example:
//
//	shop.hcl:14,3-18: Invalid name; Service name "Web_1" is not a DNS-1123 label…
func FormatDiagnostics(diags hcl.Diagnostics) string {
	if len(diags) == 0 {
		return ""
	}
	var b strings.Builder
	for _, d := range diags {
		b.WriteString(FormatDiagnostic(d))
		b.WriteByte('\n')
	}
	return b.String()
}

// FormatDiagnostic renders one diagnostic.
func FormatDiagnostic(d *hcl.Diagnostic) string {
	severity := "Error"
	if d.Severity == hcl.DiagWarning {
		severity = "Warning"
	}
	var b strings.Builder
	if d.Subject != nil {
		fmt.Fprintf(&b, "%s: ", d.Subject)
	}
	fmt.Fprintf(&b, "%s: %s", severity, d.Summary)
	if d.Detail != "" {
		fmt.Fprintf(&b, "; %s", d.Detail)
	}
	return b.String()
}

// HasErrors reports whether any diagnostic is an error (warnings are not).
func HasErrors(diags hcl.Diagnostics) bool { return diags.HasErrors() }
