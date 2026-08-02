import { describe, expect, it } from 'vitest'
import { isActive, matchPath } from './paths'

describe('matchPath', () => {
  it('matches a literal path', () => {
    expect(matchPath('/services', '/services')).toEqual({})
    expect(matchPath('/services', '/projects')).toBeNull()
  })

  it('captures dynamic segments', () => {
    expect(matchPath('/services/:project/:service', '/services/shop/web')).toEqual({
      project: 'shop',
      service: 'web',
    })
  })

  // A shorter or longer path is a different route, not a partial match.
  it('requires the same number of segments', () => {
    expect(matchPath('/services/:project/:service', '/services/shop')).toBeNull()
    expect(matchPath('/services/:project/:service', '/services/shop/web/logs')).toBeNull()
  })

  it('ignores trailing slashes', () => {
    expect(matchPath('/services', '/services/')).toEqual({})
  })

  it('decodes a segment, since names travel through a URL', () => {
    expect(matchPath('/services/:project/:service', '/services/shop/my%2Dweb')).toEqual({
      project: 'shop',
      service: 'my-web',
    })
  })

  // A malformed escape should not throw; it simply will not name anything real.
  it('survives a malformed escape', () => {
    expect(() => matchPath('/services/:project/:service', '/services/shop/%E0%A4%A')).not.toThrow()
  })
})

describe('isActive', () => {
  it('matches the root only exactly', () => {
    expect(isActive('/', '/', true)).toBe(true)
    expect(isActive('/services', '/', true)).toBe(false)
  })

  it('matches a section by prefix', () => {
    expect(isActive('/services/shop/web', '/services', false)).toBe(true)
    expect(isActive('/projects', '/services', false)).toBe(false)
  })
})
