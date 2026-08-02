import { describe, expect, it } from 'vitest'
import { servicesResponseSchema, subscriptionKey, Topic } from './api'

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
