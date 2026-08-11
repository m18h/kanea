import { describe, expect, it } from 'vitest'
import { matchesQuery } from '@/lib/search'

describe('matchesQuery', () => {
  it('matches a case-insensitive substring in any field', () => {
    expect(matchesQuery('API', 'web/api-server', 'nginx:1.27')).toBe(true)
    expect(matchesQuery('nginx', 'web/api-server', 'nginx:1.27')).toBe(true)
    expect(matchesQuery('postgres', 'web/api-server', 'nginx:1.27')).toBe(false)
  })

  it('matches everything on an empty or whitespace query', () => {
    // A cleared search box is the unfiltered list, not an empty one.
    expect(matchesQuery('', 'anything')).toBe(true)
    expect(matchesQuery('   ', 'anything')).toBe(true)
    expect(matchesQuery('', undefined)).toBe(true)
  })

  it('skips absent fields rather than matching on them', () => {
    expect(matchesQuery('undefined', undefined, 'real value')).toBe(false)
  })
})
