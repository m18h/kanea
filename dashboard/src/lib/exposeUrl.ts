import type { Service } from '@/lib/api'

/**
 * exposeUrls lists the public addresses of a service, in the order the spec
 * declares them.
 *
 * A service can have several: `expose` takes a list of domains, and since
 * v1.50 it can appear more than once (the extra blocks ride `extra_exposes`,
 * with `Expose` staying the primary route). So this returns every one, and the
 * caller offers a choice when there is more than a single address.
 *
 * An address is omitted rather than guessed in one case: an `expose` block
 * with no domains is served at an FQDN generated under the node's
 * `--base-domain`, which lives behind `GET /v1/settings` and is **admin-only**.
 * Rather than show the control to some roles and not others, or fetch a route
 * a viewer is refused, that route contributes nothing. A wrong URL is worse
 * than an absent one.
 *
 * The scheme is the one judgement call, and it is per route. `TLSMode` is
 * empty whenever the node decides (R20: resolution happens node-side, because
 * `toDesired` runs client-side and baking a default in would make one spec
 * mean different things on two machines), so the dashboard cannot read it off
 * the record. https is the right guess: `--tls-default` is `acme` unless an
 * operator changed it, and plaintext is the opt-in. Only an explicit
 * `plaintext` produces an http URL.
 */
export function exposeUrls(desired: Service): string[] {
  const routes = [desired.Expose, ...(desired.extra_exposes ?? [])]
  const out: string[] = []
  for (const route of routes) {
    if (!route) continue
    const scheme = route.TLSMode === 'plaintext' ? 'http' : 'https'
    for (const domain of route.Domains ?? []) {
      const host = domain.trim()
      if (!host) continue
      const url = `${scheme}://${host}`
      // A domain declared on two routes is one address, not two entries in a
      // menu that look identical and go to the same place.
      if (!out.includes(url)) out.push(url)
    }
  }
  return out
}
