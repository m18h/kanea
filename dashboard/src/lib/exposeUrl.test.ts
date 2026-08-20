import { describe, expect, it } from 'vitest'
import { exposeUrls } from '@/lib/exposeUrl'
import type { Service } from '@/lib/api'

/**
 * The public addresses the detail page's Open control offers.
 *
 * A service can have several — `expose` takes a list of domains, and since
 * v1.50 the block itself can repeat — so this returns all of them. The rule
 * that matters most is when an address is *omitted*: a wrong URL is worse than
 * an absent one, and an expose with no domains has an address the dashboard
 * cannot resolve, because the generated FQDN needs the node's base domain and
 * that route is admin-only.
 */

function svc(over: Partial<Service> = {}): Service {
  return {
    Project: 'shop',
    Service: 'web',
    Count: 1,
    Image: 'img:1',
    Resources: { CPUMillis: 0, MemoryBytes: 0 },
    ...over,
  }
}

describe('exposeUrls', () => {
  it('is https for a domain whose TLS the node resolves', () => {
    // The common case: R20 leaves TLSMode empty because resolution happens on
    // the node, and the node's default is acme.
    expect(exposeUrls(svc({ Expose: { Port: 3000, Domains: ['shop.example.com'] } }))).toEqual([
      'https://shop.example.com',
    ])
  })

  it('is https for every declared mode except plaintext', () => {
    for (const mode of ['acme', 'self-signed', 'provided']) {
      expect(
        exposeUrls(svc({ Expose: { Port: 3000, Domains: ['a.example.com'], TLSMode: mode } })),
      ).toEqual(['https://a.example.com'])
    }
  })

  it('is http only when plaintext is explicit', () => {
    expect(
      exposeUrls(
        svc({ Expose: { Port: 3000, Domains: ['a.example.com'], TLSMode: 'plaintext' } }),
      ),
    ).toEqual(['http://a.example.com'])
  })

  it('lists every domain on a route, in declaration order', () => {
    expect(
      exposeUrls(
        svc({ Expose: { Port: 3000, Domains: ['shop.example.com', 'www.shop.example.com'] } }),
      ),
    ).toEqual(['https://shop.example.com', 'https://www.shop.example.com'])
  })

  it('includes the extra routes v1.50 added, each with its own scheme', () => {
    expect(
      exposeUrls(
        svc({
          Expose: { Port: 3000, Domains: ['shop.example.com'] },
          extra_exposes: [
            { Port: 3000, Domains: ['admin.example.com'] },
            { Port: 8080, Domains: ['internal.example.com'], TLSMode: 'plaintext' },
          ],
        }),
      ),
    ).toEqual([
      'https://shop.example.com',
      'https://admin.example.com',
      'http://internal.example.com',
    ])
  })

  it('does not repeat one address declared on two routes', () => {
    expect(
      exposeUrls(
        svc({
          Expose: { Port: 3000, Domains: ['shop.example.com'] },
          extra_exposes: [{ Port: 8080, Domains: ['shop.example.com'] }],
        }),
      ),
    ).toEqual(['https://shop.example.com'])
  })

  it('is empty for an internal service', () => {
    expect(exposeUrls(svc())).toEqual([])
  })

  it('omits a route with no domains: the FQDN is generated node-side', () => {
    expect(exposeUrls(svc({ Expose: { Port: 3000 } }))).toEqual([])
    expect(exposeUrls(svc({ Expose: { Port: 3000, Domains: [] } }))).toEqual([])
    // A blank entry is not a domain either.
    expect(exposeUrls(svc({ Expose: { Port: 3000, Domains: ['  '] } }))).toEqual([])
    // And an unresolvable route does not suppress a resolvable sibling.
    expect(
      exposeUrls(
        svc({
          Expose: { Port: 3000 },
          extra_exposes: [{ Port: 3000, Domains: ['admin.example.com'] }],
        }),
      ),
    ).toEqual(['https://admin.example.com'])
  })
})
