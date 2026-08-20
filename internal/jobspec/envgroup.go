package jobspec

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"

	"github.com/m18h/kanea/internal/secrets"
)

// Env groups (PRD §6.2 R34).
//
// A group is declared once and *taken* by a service, which is the difference
// from R30's variables: a variable substitutes into text you write, so sharing
// an environment with it still means writing every key in every service.
//
// Two properties decide the implementation. Groups are **opt-in per service**
// rather than project-wide, because Env is SpecHash material and a project-wide
// default would make a one-line edit roll every service in the project - the
// blast radius has to be something the spec states. And a group is **evaluated
// once per consuming service**, never once per spec, because a value may carry
// ${service.db.host} and that namespace is project-scoped: one group taken from
// two projects resolves to two different addresses, and the R9/R10 dependency
// edge belongs to the service that took it.

// envGroupExprs returns a group's value expressions, for reference collection.
func envGroupExprs(g *EnvGroup) []hcl.Expression {
	attrs, diags := g.Body.JustAttributes()
	if diags.HasErrors() {
		return nil // validateEnvGroups reports it
	}
	out := make([]hcl.Expression, 0, len(attrs))
	for _, attr := range attrs {
		out = append(out, attr.Expr)
	}
	return out
}

// evalEnvGroup evaluates one group against a consuming service's context.
//
// A null value is skipped rather than stored, which is evalEnv's existing rule
// and gives "unset this key" for free: a later group, or the service's own env,
// can null out a key an earlier group set.
func evalEnvGroup(g *EnvGroup, ctx *hcl.EvalContext) (map[string]string, hcl.Diagnostics) {
	attrs, diags := g.Body.JustAttributes()
	if diags.HasErrors() {
		return nil, diags
	}
	out := make(map[string]string, len(attrs))
	for name, attr := range attrs {
		val, valDiags := attr.Expr.Value(ctx)
		diags = append(diags, valDiags...)
		if valDiags.HasErrors() || val.IsNull() {
			continue
		}
		str, err := convert.Convert(val, cty.String)
		if err != nil || str.IsNull() {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Invalid env group value",
				Detail: fmt.Sprintf("env_group %q sets %q to a value that is not a string, "+
					"number or bool. Environment values are primitives (R30's rule).",
					g.Name, name),
				Subject: attr.Range.Ptr(),
			})
			continue
		}
		out[name] = str.AsString()
	}
	return out, diags
}

// validateEnvGroups enforces R34's declaration and reference rules.
//
// The R5 half is deliberately not here: a group is top-level and knows no
// project, so a `secret:` inside one is scoped against every service that takes
// it, in validateEnvGroupRefs below. That is v1.72's `storage.auth_ref` rule
// applied to a second top-level block, and it is why a group carrying one
// project's secret is legal until somebody in another project takes it.
func validateEnvGroups(spec *Spec) hcl.Diagnostics {
	var diags hcl.Diagnostics

	seen := map[string]hcl.Range{}
	for _, g := range spec.EnvGroups {
		diags = append(diags, validateName("Env group", g.Name, g.DefRange)...)
		if prev, dup := seen[g.Name]; dup {
			diags = append(diags, &hcl.Diagnostic{
				Severity: hcl.DiagError,
				Summary:  "Duplicate env group",
				Detail: fmt.Sprintf("env_group %q is already declared at %s. Names are how a "+
					"service takes a group, so two of them would be ambiguous.",
					g.Name, prev),
				Subject: g.DefRange.Ptr(),
			})
		}
		seen[g.Name] = g.DefRange
	}

	for _, svc := range spec.Services {
		taken := map[string]bool{}
		for _, name := range svc.EnvFrom {
			if spec.EnvGroupByName(name) == nil {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Unknown env group",
					Detail: fmt.Sprintf("Service %q takes env_group %q, which is not declared "+
						"in this set.", svc.Name, name),
					Subject: svc.DefRange.Ptr(),
				})
				continue
			}
			if taken[name] {
				diags = append(diags, &hcl.Diagnostic{
					Severity: hcl.DiagError,
					Summary:  "Duplicate env group reference",
					Detail: fmt.Sprintf("Service %q lists env_group %q twice in env_from. "+
						"Order decides precedence, so a repeat is ambiguous rather than harmless.",
						svc.Name, name),
					Subject: svc.DefRange.Ptr(),
				})
			}
			taken[name] = true
		}
		diags = append(diags, validateEnvGroupRefs(spec, svc)...)
	}
	return diags
}

// validateEnvGroupRefs applies R5 to a group's secret references, once per
// consuming service.
//
// This is the whole reason a group can be top-level and still be safe: the
// group does not know a project, so the check happens where one exists. A group
// holding `secret:shop/db` is fine for a service in `shop` and refused for a
// service in `analytics`, and the refusal names both.
func validateEnvGroupRefs(spec *Spec, svc *Service) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, name := range svc.EnvFrom {
		group := spec.EnvGroupByName(name)
		if group == nil {
			continue
		}
		attrs, attrDiags := group.Body.JustAttributes()
		if attrDiags.HasErrors() {
			continue
		}
		for key, attr := range attrs {
			literal, ok := literalString(attr.Expr)
			if !ok {
				// A value that is not a literal (an interpolation) cannot be
				// scoped statically; the substituted result is checked by
				// validateSecretRefs once the service's env is merged.
				continue
			}
			ref, _, isRef := secrets.ParseEnvRef(literal)
			if !isRef {
				continue
			}
			diags = append(diags, checkSecretRef(ref, svc.Project,
				fmt.Sprintf("%s in env_group %q, taken by service %q", key, name, svc.Name),
				attr.Range)...)
		}
	}
	return diags
}

// literalString reports whether an expression is a bare string literal.
func literalString(expr hcl.Expression) (string, bool) {
	val, diags := expr.Value(nil)
	if diags.HasErrors() || val.IsNull() || val.Type() != cty.String {
		return "", false
	}
	return val.AsString(), true
}
