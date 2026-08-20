package jobspec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"

	"github.com/m18h/kanea/internal/secrets"
)

// Secret interpolation inside a `file` block's content (PRD §6.2 R35).
//
// `${secret.<scope>.<name>}` must put a secret's *value* into a config file
// without the value ever entering the Store, an API response, a backup or a log
// (AGENTS.md constraint #4). It therefore resolves at parse to an opaque
// placeholder and is substituted on the node at alloc create, which is R3's
// rule for an env var applied to bytes: the record keeps the reference, so a
// rotation lands at the next replacement and a restart re-resolves.
//
// The mechanism is the one `${GIT_SHA_SHORT}` already uses (varContext): a
// reference that survives parsing because its value does not exist yet. Here it
// survives because its value must not exist here at all.

// SecretNamespace is the root of a secret interpolation, and a name no spec may
// declare as a variable (R30's reserved list).
const SecretNamespace = "secret"

// secretInterp collects the references one file's content makes.
type secretInterp struct {
	nonce string
	refs  []string
	index map[string]int
}

func newSecretInterp() (*secretInterp, error) {
	buf := make([]byte, secrets.NonceBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generate secret placeholder nonce: %w", err)
	}
	return &secretInterp{nonce: hex.EncodeToString(buf), index: map[string]int{}}, nil
}

// placeholderFor returns the placeholder for a reference, adding it to the
// table on first use. Repeating one reference reuses its index rather than
// growing the table, so a file naming the same secret twice carries it once.
func (s *secretInterp) placeholderFor(ref string) string {
	i, seen := s.index[ref]
	if !seen {
		i = len(s.refs)
		s.index[ref] = i
		s.refs = append(s.refs, ref)
	}
	return secrets.PlaceholderText(s.nonce, i)
}

// secretContext builds the `secret` object for one file's content expression.
//
// cty has no open-ended object, so the names cannot be invented: they are
// discovered from the expression itself by walking its traversals, the same
// walk collectRefs does for `service`. That is also what bounds the work - a
// file that names no secret builds nothing.
//
// Every discovered reference is R5-scoped here, at the call site, so the
// diagnostic carries the line the author wrote rather than a later failure.
func secretContext(
	expr hcl.Expression, project, where string, interp *secretInterp,
) (cty.Value, hcl.Diagnostics) {
	var diags hcl.Diagnostics
	scopes := map[string]map[string]cty.Value{}

	for _, tr := range expr.Variables() {
		if tr.RootName() != SecretNamespace {
			continue
		}
		scope, name, ok := parseSecretTraversal(tr, &diags)
		if !ok {
			continue
		}
		ref := SecretPrefix + scope + "/" + name
		// R5, at the point of use. A file is service-scoped, so unlike an env
		// group there is exactly one project to check against.
		if d := checkSecretRef(ref, project, where, tr.SourceRange()); d.HasErrors() {
			diags = append(diags, d...)
			continue
		}
		if scopes[scope] == nil {
			scopes[scope] = map[string]cty.Value{}
		}
		scopes[scope][name] = cty.StringVal(interp.placeholderFor(ref))
	}

	out := map[string]cty.Value{}
	for scope, names := range scopes {
		out[scope] = cty.ObjectVal(names)
	}
	if len(out) == 0 {
		// An empty object still has to exist: without it a traversal that only
		// failed validation would produce HCL's "unsupported attribute" on top
		// of the diagnostic already reported.
		return cty.EmptyObjectVal, diags
	}
	return cty.ObjectVal(out), diags
}

// parseSecretTraversal reads ${secret.<scope>.<name>} into its two halves.
//
// Both an attribute and a string index are accepted, because traversalName
// accepts both: `secret.shop.db_password` reads best, and
// `secret.shop["database-password"]` is the form any name that is not a bare
// identifier needs - which is most real secret names.
func parseSecretTraversal(tr hcl.Traversal, diags *hcl.Diagnostics) (string, string, bool) {
	bad := func(detail string) {
		*diags = append(*diags, &hcl.Diagnostic{
			Severity: hcl.DiagError,
			Summary:  "Invalid secret reference",
			Detail:   detail,
			Subject:  tr.SourceRange().Ptr(),
		})
	}
	if len(tr) != 3 {
		bad("A secret reference is ${secret.<scope>.<name>}, for example " +
			"${secret.shop.api_key} or ${secret.shop[\"database-password\"]}.")
		return "", "", false
	}
	scope, ok := traversalName(tr[1])
	if !ok {
		bad("The secret's scope must be a literal, e.g. ${secret.shop.api_key}.")
		return "", "", false
	}
	name, ok := traversalName(tr[2])
	if !ok {
		bad("The secret's name must be a literal, e.g. ${secret.shop.api_key}.")
		return "", "", false
	}
	if scope == "" || name == "" {
		bad("A secret reference needs both a scope and a name.")
		return "", "", false
	}
	return scope, name, true
}

// checkNoNUL refuses a NUL byte in file content.
//
// It is what makes a placeholder inexpressible rather than merely improbable: a
// config file containing NUL is not a config file, and with the byte refused no
// author-supplied text can form a placeholder at all, whatever nonce it guesses.
// The apply seam needs this check as much as the parser does, because there
// content arrives base64-encoded and NUL is perfectly expressible.
//
// Callers pass content with this file's own placeholders already stripped.
func checkNoNUL(content []byte, what string) error {
	if i := strings.IndexByte(string(content), 0); i >= 0 {
		return fmt.Errorf("%s contains a NUL byte at offset %d; file content must be text", what, i)
	}
	return nil
}
