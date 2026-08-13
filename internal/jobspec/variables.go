package jobspec

import (
	"fmt"
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
)

// Shared variables (PRD §6.2 R30, v1.63). A top-level `variables { }` block
// names values the rest of the spec references as ${name} — the same flat
// vocabulary as the R2 built-ins, evaluated by the one EvalContext the whole
// decode already runs against. The blocks are extracted and evaluated here,
// *before* the structural decode, so their results are in scope for it.

// reservedVarNames may not be declared as variables at any level: the R2
// built-ins, whose values belong to the caller, and `service`, which is the
// env pass's root object (R9, resolve.go).
var reservedVarNames = map[string]string{
	"GIT_SHA":       "a build-time built-in (R2)",
	"GIT_SHA_SHORT": "a build-time built-in (R2)",
	"GIT_BRANCH":    "a build-time built-in (R2)",
	"KANEA_PROJECT": "a built-in (R2)",
	"service":       "the service-reference namespace (R9)",
}

// variablesSchema pulls just the variables blocks out of the merged body,
// leaving everything else for the structural decode.
var variablesSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{{Type: "variables"}},
}

// specVariables evaluates every top-level variables block. A value may
// reference node variables and built-ins — the definition context deliberately
// excludes the spec's own variables, so a sibling reference fails as an
// unknown variable rather than opening an ordering-and-cycles story (R30).
func specVariables(body hcl.Body, opts Options) (map[string]string, hcl.Diagnostics) {
	content, _, diags := body.PartialContent(variablesSchema)
	if content == nil || len(content.Blocks) == 0 {
		return nil, diags
	}

	defCtx := varContext(overlayVars(opts.NodeVars, opts.Vars))
	vars := map[string]string{}
	declared := map[string]hcl.Range{}
	for _, block := range content.Blocks {
		attrs, attrDiags := block.Body.JustAttributes()
		diags = append(diags, attrDiags...)
		for _, attr := range attrsInSourceOrder(attrs) {
			if why, reserved := reservedVarNames[attr.Name]; reserved {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Reserved variable name",
					Detail:   fmt.Sprintf("%q is %s and cannot be declared as a variable.", attr.Name, why),
					Subject:  attr.Range.Ptr(),
				})
				continue
			}
			if first, dup := declared[attr.Name]; dup {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Duplicate variable",
					Detail: fmt.Sprintf("Variable %q is already declared at %s.",
						attr.Name, first),
					Subject: attr.Range.Ptr(),
				})
				continue
			}
			declared[attr.Name] = attr.Range

			v, valDiags := attr.Expr.Value(defCtx)
			diags = append(diags, valDiags...)
			if valDiags.HasErrors() {
				continue
			}
			s, err := variableString(v)
			if err != nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Invalid variable value",
					Detail:   fmt.Sprintf("Variable %q: %s.", attr.Name, err),
					Subject:  attr.Range.Ptr(),
				})
				continue
			}
			vars[attr.Name] = s
		}
	}
	if diags.HasErrors() {
		return nil, diags
	}
	return vars, diags
}

// attrsInSourceOrder returns a body's attributes ordered by their position,
// so "already declared at" always names the earlier occurrence and the
// diagnostics do not depend on map iteration order.
func attrsInSourceOrder(attrs hcl.Attributes) []*hcl.Attribute {
	out := make([]*hcl.Attribute, 0, len(attrs))
	for _, attr := range attrs {
		out = append(out, attr)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Range, out[j].Range
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Start.Byte < b.Start.Byte
	})
	return out
}

// variableString renders a primitive value as the string the ${} vocabulary
// carries. A list or object is refused by name (R30): the flat vocabulary has
// no way to reference an element, so accepting one would accept a value
// nothing can read.
func variableString(v cty.Value) (string, error) {
	if v.IsNull() {
		return "", fmt.Errorf("the value is null")
	}
	if !v.Type().IsPrimitiveType() {
		return "", fmt.Errorf("a %s is not a variable value; use a string, number or bool", v.Type().FriendlyName())
	}
	s, err := convert.Convert(v, cty.String)
	if err != nil {
		return "", err
	}
	return s.AsString(), nil
}

// overlayVars merges maps left to right, later entries winning — the R30
// precedence chain is overlayVars(node, spec, caller).
func overlayVars(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}
