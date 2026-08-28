import type { RenderResponse } from './spec'

/**
 * The inline editor's scope check (PRD §12.2, v1.103).
 *
 * The service detail page's editor speaks for one service. A render tells us
 * what the edited text means; this module decides whether that meaning stays
 * inside the page's scope, and refuses - naming the fields in the spec's own
 * vocabulary, the `fieldsLostByImageApply` doctrine - when it does not. The
 * check is fail-closed but it is a page-scope courtesy, not a security
 * boundary: the same admin has the full editor one link away.
 *
 * Pure on purpose (the lib/settings.ts pattern): the component renders the
 * verdict, the table test owns the semantics.
 */

/**
 * Wire keys on a Desired record that an inline single-service edit may not
 * change, labelled in the spec's vocabulary. Key casing matches
 * internal/reconciler/types.go: pre-v1.84 fields marshal under their Go name
 * (PascalCase, nil slices as null), later fields are lowercase omitempty.
 * Moving the boundary is an edit to this list plus its table test.
 */
export const EXTERNAL_FIELDS: readonly { label: string; keys: readonly string[] }[] = [
  { label: 'volumes', keys: ['Volumes'] },
  { label: 'device grants', keys: ['Devices'] },
  { label: 'socket grants', keys: ['Sockets'] },
  { label: 'runtime', keys: ['runtime'] },
  { label: 'function config', keys: ['function'] },
  // Expose, extra_exposes and Publish are deliberately editable inline: they
  // are declared inside the service block and belong to the service (v1.103).
]

export type ScopeVerdict =
  | { ok: true }
  | {
      ok: false
      reason:
        | 'invalid'
        | 'no-service'
        | 'multiple-services'
        | 'wrong-service'
        | 'pipelines'
        | 'missing-baseline'
        | 'external-change'
      changed?: string[]
      message: string
    }

/**
 * normalizeForCompare collapses the wire's three spellings of absence - a Go
 * nil slice's `null`, a parser's `[]`, an omitted `omitempty` key - into one,
 * and rebuilds objects with sorted keys so JSON.stringify is stable. Every
 * excluded field crosses at least one of those seams between the render
 * result and the stored record; without this, an untouched volume block would
 * read as a change.
 */
export function normalizeForCompare(v: unknown): unknown {
  if (v === null || v === undefined) return undefined
  if (Array.isArray(v)) {
    if (v.length === 0) return undefined
    return v.map((item) => normalizeForCompare(item) ?? null)
  }
  if (typeof v === 'object') {
    const entries = Object.entries(v as Record<string, unknown>)
      .map(([k, val]) => [k, normalizeForCompare(val)] as const)
      .filter(([, val]) => val !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    if (entries.length === 0) return undefined
    return Object.fromEntries(entries)
  }
  return v
}

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(normalizeForCompare(a)) === JSON.stringify(normalizeForCompare(b))
}

/**
 * checkScope decides whether a rendered edit stays within one service's
 * scope. `current` is the stored record from an HTTP `GET /v1/services` read:
 * never the websocket topic (it elides file contents) and never the page's
 * zod-parsed record (parsing strips the very keys compared here). Server-owned
 * fields are exempt by construction - only the excluded keys are ever
 * compared.
 */
export function checkScope({
  project,
  service,
  rendered,
  current,
}: {
  project: string
  service: string
  rendered: RenderResponse
  current: Record<string, unknown> | undefined
}): ScopeVerdict {
  const target = `${project}/${service}`
  if (!rendered.valid) {
    return { ok: false, reason: 'invalid', message: 'The spec did not validate.' }
  }
  const services = rendered.services ?? []
  if (services.length === 0) {
    return {
      ok: false,
      reason: 'no-service',
      message: `The spec declares no service; this editor edits ${target}.`,
    }
  }
  if (services.length > 1) {
    return {
      ok: false,
      reason: 'multiple-services',
      message: `The spec declares ${services.length} services; this editor edits only ${target}. Use the full spec editor for the rest.`,
    }
  }
  const svc = services[0] as unknown as Record<string, unknown>
  const declared = `${String(svc['Project'])}/${String(svc['Service'])}`
  if (declared !== target) {
    return {
      ok: false,
      reason: 'wrong-service',
      message: `The spec declares ${declared}; this editor edits ${target}. Use the full spec editor to rename or add services.`,
    }
  }
  if ((rendered.pipelines ?? []).length > 0) {
    return {
      ok: false,
      reason: 'pipelines',
      message: `The spec declares a project pipeline; edit that in the full spec editor.`,
    }
  }
  if (current === undefined) {
    return {
      ok: false,
      reason: 'missing-baseline',
      message: `The current record for ${target} could not be read; it may have been removed. Validate again.`,
    }
  }

  const changed = EXTERNAL_FIELDS.filter((field) =>
    field.keys.some((key) => !sameValue(svc[key], current[key])),
  ).map((field) => field.label)
  if (changed.length > 0) {
    return {
      ok: false,
      reason: 'external-change',
      changed,
      message: `An inline edit may not change ${changed.join(', ')}; open the full spec editor for those.`,
    }
  }
  return { ok: true }
}
