import { describe, expect, it } from 'vitest'
import { checkScope, normalizeForCompare, EXTERNAL_FIELDS } from './specScope'
import type { RenderResponse } from './spec'

// A minimal rendered Desired the way the daemon serializes one: pre-v1.84
// fields under their Go names (nil slices as null), later fields lowercase.
function desired(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    Project: 'shop',
    Service: 'web',
    Count: 2,
    Image: 'nginx:1.29',
    Command: null,
    Env: null,
    Volumes: null,
    Devices: null,
    Sockets: null,
    Ports: [{ Name: 'http', Container: 80 }],
    ...overrides,
  }
}

function render(
  services: Record<string, unknown>[],
  extra: Partial<RenderResponse> = {},
): RenderResponse {
  return {
    valid: true,
    diagnostics: [],
    services: services as RenderResponse['services'],
    ...extra,
  }
}

const input = (
  rendered: RenderResponse,
  current: Record<string, unknown> | undefined,
) => ({ project: 'shop', service: 'web', rendered, current })

describe('normalizeForCompare', () => {
  // The wire's three spellings of absence: a Go nil slice's null, a parser's
  // [], an omitted omitempty key. All must compare equal.
  it('collapses null, [] and {} to absent', () => {
    expect(normalizeForCompare(null)).toBeUndefined()
    expect(normalizeForCompare([])).toBeUndefined()
    expect(normalizeForCompare({})).toBeUndefined()
    expect(normalizeForCompare({ a: null, b: [] })).toBeUndefined()
  })

  it('sorts object keys so stringify is stable', () => {
    expect(JSON.stringify(normalizeForCompare({ b: 1, a: 2 }))).toBe(
      JSON.stringify(normalizeForCompare({ a: 2, b: 1 })),
    )
  })

  it('keeps array order: a reorder is a change', () => {
    expect(JSON.stringify(normalizeForCompare([1, 2]))).not.toBe(
      JSON.stringify(normalizeForCompare([2, 1])),
    )
  })
})

describe('checkScope', () => {
  const volume = { Name: 'data', Storage: 'media', Path: '/data' }
  const cases: {
    name: string
    rendered: RenderResponse
    current: Record<string, unknown> | undefined
    want: { ok: true } | { reason: string; changed?: string[] }
  }[] = [
    {
      name: 'identical record is in scope',
      rendered: render([desired()]),
      current: desired(),
      want: { ok: true },
    },
    {
      name: 'null vs missing vs empty excluded keys are all absent',
      rendered: render([desired({ Volumes: [], Devices: null })]),
      current: (() => {
        const d = desired()
        delete d['Volumes']
        delete d['Devices']
        return d
      })(),
      want: { ok: true },
    },
    {
      name: 'service-field edits are the point',
      rendered: render([
        desired({ Image: 'nginx:1.30', Count: 5, Env: { MODE: 'fast' }, args: ['--fast'] }),
      ]),
      current: desired(),
      want: { ok: true },
    },
    {
      name: 'expose and publish edits are deliberately in scope',
      rendered: render([
        desired({
          Expose: { Port: 80, Domains: ['web.example.com'] },
          Publish: [{ Port: 'http', Host: 8080 }],
        }),
      ]),
      current: desired(),
      want: { ok: true },
    },
    {
      name: 'server-owned fields present only in the baseline are exempt',
      rendered: render([desired()]),
      current: desired({
        generation: 5,
        pinned_image: 'nginx@sha256:abc',
        rollback_image: 'nginx@sha256:def',
        image_checked_at: '2026-08-28T00:00:00Z',
        spec_hash: 'deadbeef',
      }),
      want: { ok: true },
    },
    {
      name: 'an added volume is refused by name',
      rendered: render([desired({ Volumes: [volume] })]),
      current: desired(),
      want: { reason: 'external-change', changed: ['volumes'] },
    },
    {
      name: 'a removed device grant is refused by name',
      rendered: render([desired()]),
      current: desired({ Devices: [{ Grant: 'gpu' }] }),
      want: { reason: 'external-change', changed: ['device grants'] },
    },
    {
      name: 'a changed socket grant is refused by name',
      rendered: render([desired({ Sockets: [{ Grant: 'containerd' }] })]),
      current: desired({ Sockets: [{ Grant: 'docker' }] }),
      want: { reason: 'external-change', changed: ['socket grants'] },
    },
    {
      name: 'runtime and function edits are refused by name',
      rendered: render([desired({ runtime: 'wasmtime', function: { trigger: 'cron' } })]),
      current: desired({ runtime: 'wasmtime', function: { trigger: 'http' } }),
      want: { reason: 'external-change', changed: ['function config'] },
    },
    {
      name: 'several external changes name every field, in list order',
      rendered: render([desired({ Volumes: [volume], runtime: 'wasmtime' })]),
      current: desired({ Devices: [{ Grant: 'gpu' }] }),
      want: { reason: 'external-change', changed: ['volumes', 'device grants', 'runtime'] },
    },
    {
      name: 'two services are out of scope',
      rendered: render([desired(), desired({ Service: 'worker' })]),
      current: desired(),
      want: { reason: 'multiple-services' },
    },
    {
      name: 'a renamed service is out of scope',
      rendered: render([desired({ Service: 'web2' })]),
      current: desired(),
      want: { reason: 'wrong-service' },
    },
    {
      name: 'a pipeline declaration is out of scope',
      rendered: render([desired()], { pipelines: [{ project: 'shop' }] }),
      current: desired(),
      want: { reason: 'pipelines' },
    },
    {
      name: 'an invalid render is never in scope',
      rendered: { valid: false, diagnostics: [], services: null },
      current: desired(),
      want: { reason: 'invalid' },
    },
    {
      name: 'an empty render declares no service',
      rendered: render([]),
      current: desired(),
      want: { reason: 'no-service' },
    },
    {
      name: 'a missing baseline refuses rather than assuming',
      rendered: render([desired()]),
      current: undefined,
      want: { reason: 'missing-baseline' },
    },
  ]

  for (const c of cases) {
    it(c.name, () => {
      const verdict = checkScope(input(c.rendered, c.current))
      if ('ok' in c.want && c.want.ok) {
        expect(verdict).toEqual({ ok: true })
        return
      }
      expect(verdict.ok).toBe(false)
      if (verdict.ok) return
      expect(verdict.reason).toBe((c.want as { reason: string }).reason)
      const wantChanged = (c.want as { changed?: string[] }).changed
      if (wantChanged) {
        expect(verdict.changed).toEqual(wantChanged)
        for (const label of wantChanged) {
          expect(verdict.message).toContain(label)
        }
      }
      expect(verdict.message).toBeTruthy()
    })
  }

  it('every excluded field has a spec-vocabulary label', () => {
    for (const field of EXTERNAL_FIELDS) {
      expect(field.label).toMatch(/^[a-z ]+$/)
      expect(field.keys.length).toBeGreaterThan(0)
    }
  })
})
