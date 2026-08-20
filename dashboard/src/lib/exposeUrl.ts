import type { Service } from '@/lib/api'

/**
 * exposeUrl is the public address of a service's primary route, or null when
 * the dashboard cannot know it.
 *
 * Null rather than a guess, in two cases that look similar and are not:
 *
 *   - no `expose` block at all: the service is internal, and there is no
 *     public URL to offer;
 *   - an `expose` block with no domains: the edge serves it at an FQDN
 *     generated under the node's `--base-domain`, which lives behind
 *     `GET /v1/settings` and is **admin-only**. Rather than show the control
 *     to some roles and not others, or fetch a route a viewer is refused,
 *     the button is simply absent. A wrong URL is worse than no button.
 *
 * The scheme is the one judgement call. `TLSMode` is empty whenever the node
 * decides (R20: resolution happens node-side, because `toDesired` runs
 * client-side and baking a default in would make one spec mean different
 * things on two machines), so the dashboard genuinely cannot read it off the
 * record. https is the right guess: `--tls-default` is `acme` unless an
 * operator changed it, and plaintext is the opt-in. Only an explicit
 * `plaintext` produces an http URL.
 *
 * Only the first route is considered. `Desired.Expose` is the first expose by
 * construction (v1.50 keeps the rest on `extra_exposes`, which this API's
 * service view does not carry), so this is the service's primary domain
 * rather than an arbitrary one.
 */
export function exposeUrl(desired: Service): string | null {
  const expose = desired.Expose
  if (!expose) return null
  const domain = (expose.Domains ?? []).find((d) => d.trim() !== '')
  if (!domain) return null
  const scheme = expose.TLSMode === 'plaintext' ? 'http' : 'https'
  return `${scheme}://${domain}`
}
