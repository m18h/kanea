package secrets

import (
	"fmt"
	"strings"
)

// Secret placeholders in file content (PRD §6.2 R35).
//
// A `${secret.<scope>.<name>}` in a file's content must put the secret's value
// into the container without the value ever entering the Store (AGENTS.md
// constraint #4). It resolves at parse to a placeholder, and the reconciler
// substitutes on the node at alloc create.
//
// The format lives here for the reason ParseEnvRef does: three packages have to
// agree about it and none of them may own it. jobspec emits placeholders,
// internal/api re-validates records that never met the parser, and
// internal/reconciler substitutes them. A second spelling anywhere would be a
// file that renders a placeholder to a workload, or a hash that changes on
// every parse.

// PlaceholderPrefix and PlaceholderSuffix bracket a placeholder.
//
// NUL delimits because it cannot occur in a config file worth calling one, and
// content carrying it is refused outright - which is what makes a placeholder
// inexpressible by an author rather than merely unlikely to be typed.
const (
	PlaceholderPrefix = "\x00kanea:secret:"
	PlaceholderSuffix = "\x00"
)

// NonceBytes is the length of the per-parse random value a placeholder carries.
//
// The nonce is what makes a placeholder unforgeable rather than obscure: it is
// drawn after the content is read, so an author who types the placeholder text
// verbatim would have to guess a value the parse has not chosen yet. A
// placeholder with the wrong nonce is left alone, which is exactly right: a
// config file that legitimately contains the marker renders it as written.
const NonceBytes = 16

// PlaceholderText is the one place a placeholder's spelling is written down.
func PlaceholderText(nonce string, i int) string {
	return fmt.Sprintf("%s%s:%d%s", PlaceholderPrefix, nonce, i, PlaceholderSuffix)
}

// StripPlaceholders removes a file's own placeholders from its content.
//
// It is how the NUL refusal stays honest: placeholders are themselves
// NUL-delimited, so checking rendered content would refuse every file that
// interpolates a secret. What must be refused is a NUL the *author* wrote, and
// what is left after removing the placeholders is exactly that.
//
// Each placeholder is reconstructed from the nonce and index rather than
// matched by pattern, so only the ones this parse actually emitted are removed
// and a NUL smuggled in beside one is still found.
func StripPlaceholders(content []byte, nonce string, refs int) []byte {
	return rewritePlaceholders(content, nonce, refs, func(int) string { return "" })
}

// CanonicalPlaceholders rewrites placeholders to a nonce-free form, for hashing
// and for comparing a generated spec against its source.
//
// Without it the SpecHash of an unchanged spec would differ on every parse -
// the nonce is fresh each time and lives *inside* the content bytes - and every
// file-bearing service on the node would roll on every apply.
func CanonicalPlaceholders(content []byte, nonce string, refs int) []byte {
	return rewritePlaceholders(content, nonce, refs, func(i int) string {
		return fmt.Sprintf("%ssecret:%d%s", PlaceholderPrefix, i, PlaceholderSuffix)
	})
}

func rewritePlaceholders(content []byte, nonce string, refs int, to func(int) string) []byte {
	if nonce == "" || refs == 0 {
		return content
	}
	out := string(content)
	for i := range refs {
		out = strings.ReplaceAll(out, PlaceholderText(nonce, i), to(i))
	}
	return []byte(out)
}
