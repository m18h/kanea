import { describe, expect, it } from 'vitest'
import { exposeUrl } from '@/lib/exposeUrl'
import type { Service } from '@/lib/api'

/**
 * The public URL the detail page's Open button points at.
 *
 * The rule that matters is when it returns *nothing*: a wrong URL is worse
 * than an absent button, and the two absent cases are different — an internal
 * service has no public address at all, while an expose with no domains has
 * one the dashboard cannot resolve, because the generated FQDN needs the
 * node's base domain and that route is admin-only.
 */

function svc(expose?: Service['Expose']): Service {
  return {
    Project: 'shop',
    Service: 'web',
    Count: 1,
    Image: 'img:1',
    Resources: { CPUMillis: 0, MemoryBytes: 0 },
    ...(expose ? { Expose: expose } : {}),
  }
}

describe('exposeUrl', () => {
  it('is https for a domain whose TLS the node resolves', () => {
    // The common case: R20 leaves TLSMode empty because resolution happens on
    // the node, and the node's default is acme.
    expect(exposeUrl(svc({ Port: 3000, Domains: ['shop.example.com'] }))).toBe(
      'https://shop.example.com',
    )
  })

  it('is https for every declared mode except plaintext', () => {
    for (const mode of ['acme', 'self-signed', 'provided']) {
      expect(exposeUrl(svc({ Port: 3000, Domains: ['a.example.com'], TLSMode: mode }))).toBe(
        'https://a.example.com',
      )
    }
  })

  it('is http only when plaintext is explicit', () => {
    expect(
      exposeUrl(svc({ Port: 3000, Domains: ['a.example.com'], TLSMode: 'plaintext' })),
    ).toBe('http://a.example.com')
  })

  it('takes the first domain: Desired.Expose is the primary route by construction', () => {
    expect(
      exposeUrl(svc({ Port: 3000, Domains: ['shop.example.com', 'www.shop.example.com'] })),
    ).toBe('https://shop.example.com')
  })

  it('is null for an internal service', () => {
    expect(exposeUrl(svc())).toBeNull()
  })

  it('is null for an expose with no domains: the FQDN is generated node-side', () => {
    expect(exposeUrl(svc({ Port: 3000 }))).toBeNull()
    expect(exposeUrl(svc({ Port: 3000, Domains: [] }))).toBeNull()
    // A blank entry is not a domain either.
    expect(exposeUrl(svc({ Port: 3000, Domains: ['  '] }))).toBeNull()
  })
})
