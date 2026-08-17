import { afterEach, describe, expect, it, vi } from 'vitest'
import { applySpec, fetchSpecSource, renderResponseSchema, HCL_TEMPLATE } from './spec'

function stubFetch(status: number, body: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn(() =>
      Promise.resolve({
        ok: status >= 200 && status < 300,
        status,
        json: () => Promise.resolve(body),
      } as Response),
    ),
  )
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('renderResponseSchema', () => {
  it('parses a diagnostic set with positions', () => {
    const parsed = renderResponseSchema.parse({
      valid: false,
      diagnostics: [
        { severity: 'error', summary: 'Missing task', file: 'editor.hcl', line: 3, column: 1 },
      ],
    })
    expect(parsed.valid).toBe(false)
    expect(parsed.diagnostics[0]?.line).toBe(3)
  })

  it('parses a valid render with services', () => {
    const parsed = renderResponseSchema.parse({
      valid: true,
      services: [{ Project: 'shop', Service: 'web', Count: 1, Image: 'nginx:1.29' }],
    })
    expect(parsed.services?.[0]?.Service).toBe('web')
  })
})

describe('applySpec', () => {
  // A 422 is a completed request whose answer is the diagnostic list: the
  // editor needs positions, not a thrown string.
  it('returns diagnostics on 422 rather than throwing', async () => {
    stubFetch(422, {
      valid: false,
      diagnostics: [{ severity: 'error', summary: 'broken', line: 2 }],
    })
    const result = await applySpec('service {}', undefined)
    expect('diagnostics' in result && result.diagnostics[0]?.summary).toBe('broken')
  })

  it('returns the applied keys on success', async () => {
    stubFetch(200, { applied: ['shop/web'], index: 7 })
    const result = await applySpec('…', 'shop', 'csrf-token')
    expect('applied' in result && result.applied).toEqual(['shop/web'])
  })

  it('throws the daemon message on other refusals', async () => {
    stubFetch(403, { error: 'port 81 is outside the permitted publish range' })
    await expect(applySpec('…', undefined)).rejects.toThrow(/publish range/)
  })
})

describe('fetchSpecSource', () => {
  it('returns the generated text', async () => {
    stubFetch(200, { hcl: 'service "web" {}', generated: true })
    const result = await fetchSpecSource('shop', 'web')
    expect('hcl' in result && result.hcl).toContain('service')
  })

  // A refusal names the field; the editor falls back to the template rather
  // than showing generated text that would apply as something else.
  it('surfaces a generation refusal as a note, not an error', async () => {
    stubFetch(422, { error: 'cannot generate a spec for shop/web: its volume blocks…' })
    const result = await fetchSpecSource('shop', 'web')
    expect('refusal' in result && result.refusal).toContain('volume')
  })
})

describe('HCL_TEMPLATE', () => {
  it('declares the minimal shape §6.1 promises', () => {
    expect(HCL_TEMPLATE).toContain('spec_version = 1')
    expect(HCL_TEMPLATE).toContain('service "web"')
    expect(HCL_TEMPLATE).toContain('resources')
  })
})
