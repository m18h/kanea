/**
 * Path matching for the dashboard's router (see lib/router.tsx).
 *
 * Separate from the components so the router file exports only components,
 * which is what keeps fast refresh working.
 */

/**
 * matchPath tests a path against a pattern with `:name` segments and returns
 * the captured values, or null when it does not match.
 */
export function matchPath(
  pattern: string,
  path: string,
): Record<string, string> | null {
  const patternParts = segments(pattern)
  const pathParts = segments(path)
  if (patternParts.length !== pathParts.length) return null

  const params: Record<string, string> = {}
  for (let i = 0; i < patternParts.length; i++) {
    const expected = patternParts[i]
    const actual = pathParts[i]
    if (expected === undefined || actual === undefined) return null

    if (expected.startsWith(':')) {
      // Decoded, because a service name reaches this through a URL. It is
      // still only ever rendered as text.
      params[expected.slice(1)] = safeDecode(actual)
      continue
    }
    if (expected !== actual) return null
  }
  return params
}

function segments(path: string): string[] {
  return path.split('/').filter((part) => part !== '')
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    // A malformed escape is not worth throwing over; the raw value simply
    // will not match anything real.
    return value
  }
}

/** isActive reports whether a nav target is the current page. */
export function isActive(path: string, to: string, exact: boolean): boolean {
  if (exact) return normalise(path) === normalise(to)
  return normalise(path).startsWith(normalise(to))
}

function normalise(path: string): string {
  const trimmed = path.replace(/\/+$/, '')
  return trimmed === '' ? '/' : trimmed
}
