import { describe, expect, it } from 'vitest'
import { servicesResponseSchema } from '@/lib/api'
import { findService, initLogLines, servicesPayload } from '../../mock/state'

// The mock's contract is its header comment: shapes match src/lib's zod
// schemas, and a field the schemas would reject is a bug here, not there.
// This parse is that sentence as a test - it is also the pairing that would
// have caught v0.31.1's bug from the other side, where the schema's `Init`
// key rejected nothing because the mock served no init steps at all.
describe('the mock daemon serves what the real schemas accept', () => {
  it('parses the services payload, init steps included', () => {
    const parsed = servicesResponseSchema.parse(servicesPayload())
    const api = parsed.services?.find((s) => s.Service === 'api')
    expect(api?.init?.map((s) => s.name)).toEqual(['wait-for-postgres', 'migrate'])
  })

  it('serves an init transcript on the leader alloc, and only for declared steps', () => {
    const api = findService('shop', 'api')
    if (!api) throw new Error('the shop/api fixture is gone')
    const lines = initLogLines(api, 'migrate')
    expect(lines.length).toBeGreaterThan(0)
    // v1.92: a sequence runs once per service, on alloc index 0.
    expect(new Set(lines.map((l) => l.alloc_id))).toEqual(new Set(['shop-api-0']))
    expect(initLogLines(api, 'no-such-step')).toEqual([])
  })
})
