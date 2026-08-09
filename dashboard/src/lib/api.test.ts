import { describe, expect, it } from 'vitest'
import { allocsResponseSchema, servicesResponseSchema, subscriptionKey, Topic } from './api'

describe('subscriptionKey', () => {
  it('is the bare topic when nothing scopes it', () => {
    expect(subscriptionKey({ topic: Topic.Services })).toBe('services')
  })

  it('includes the service so two log streams can share one socket', () => {
    expect(subscriptionKey({ topic: Topic.Logs, project: 'shop', service: 'web' })).toBe(
      'logs:shop/web',
    )
  })
})

describe('servicesResponseSchema', () => {
  it('accepts a null list, which is what Go sends for an empty slice', () => {
    const parsed = servicesResponseSchema.parse({ services: null })
    expect(parsed.services).toBeNull()
  })

  // Parsing rather than casting is the point: a daemon that changed shape
  // should fail here with a field name, not crash three components away.
  it('rejects a payload missing a required field', () => {
    const result = servicesResponseSchema.safeParse({
      services: [{ Project: 'shop', Service: 'web' }],
    })
    expect(result.success).toBe(false)
  })
})

describe('allocsResponseSchema', () => {
  // AllocRecord marshals lowercase json tags, unlike Desired's PascalCase.
  // This fixture is a real daemon payload; the PascalCase schema this replaced
  // rejected every frame the allocs topic ever sent.
  it('parses the lowercase wire shape AllocRecord actually sends', () => {
    const parsed = allocsResponseSchema.parse({
      allocs: [
        {
          id: 'shop-web-0-abc12',
          project: 'shop',
          service: 'web',
          index: 0,
          image: 'reg.kanea.dev/web:1.9.2',
          state: 'running',
          spec_hash: 'deadbeef',
          restarts: 1,
          last_exit_code: 137,
          last_exit_at: '2026-08-09T14:25:17Z',
          healthy: true,
          last_probe_at: '2026-08-09T14:32:00Z',
          created_at: '2026-06-29T08:00:00Z',
          updated_at: '2026-08-09T14:32:00Z',
        },
      ],
    })
    expect(parsed.allocs?.[0]?.id).toBe('shop-web-0-abc12')
    expect(parsed.allocs?.[0]?.created_at).toBe('2026-06-29T08:00:00Z')
  })

  it('rejects the PascalCase shape that never matched the wire', () => {
    const result = allocsResponseSchema.safeParse({
      allocs: [{ ID: 'x', Project: 'shop', Service: 'web', Index: 0, State: 'running' }],
    })
    expect(result.success).toBe(false)
  })
})
