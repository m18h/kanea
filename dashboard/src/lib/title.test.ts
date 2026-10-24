import { describe, expect, it } from 'vitest'
import { pageTitle, titleFor } from '@/lib/title'

describe('titleFor', () => {
  const cases: [path: string, want: string][] = [
    ['/', 'Dashboard · Kanea'],
    ['/projects', 'Projects · Kanea'],
    ['/services', 'Services · Kanea'],
    ['/functions', 'Functions · Kanea'],
    ['/pipelines', 'Pipelines · Kanea'],
    ['/storage', 'Storage · Kanea'],
    ['/events', 'Events · Kanea'],
    ['/backups', 'Backups · Kanea'],
    ['/updates', 'Updates · Kanea'],
    // The deploy page, not a service named "new": it has to be matched ahead
    // of the two-segment service route, as App.tsx matches it.
    ['/services/new', 'Deploy service · Kanea'],
    ['/services/shop/web', 'shop/web · Kanea'],
    ['/services/shop/web/edit', 'Edit shop/web · Kanea'],
    ['/pipelines/shop/web/a1b2c3d4e5f6', 'shop/web #a1b2c3d4 · Kanea'],
    ['/settings', 'Settings · Kanea'],
    ['/settings/accounts', 'Accounts · Settings · Kanea'],
    ['/settings/audit', 'Audit · Settings · Kanea'],
    ['/nope', 'Not found · Kanea'],
    ['/services/shop/web/nope', 'Not found · Kanea'],
  ]

  for (const [path, want] of cases) {
    it(`names ${path}`, () => {
      expect(titleFor(path)).toBe(want)
    })
  }

  // The page itself says "No such settings tab" for this, and a title naming a
  // tab the reader cannot see would be the page's only contradiction.
  it('falls back to the bare page for a settings tab that does not exist', () => {
    expect(titleFor('/settings/banana')).toBe('Settings · Kanea')
  })

  it('reads a trailing slash as the page it is', () => {
    expect(titleFor('/services/')).toBe('Services · Kanea')
  })

  // The hook is keyed on the router's `path`, which excludes the query - which
  // is what keeps a title from churning on every keystroke in a filter box.
  // titleFor is never handed one, and would not know what to do with it.
  it('is given a path, never a query string', () => {
    expect(titleFor('/services?q=api')).toBe('Not found · Kanea')
  })
})

describe('pageTitle', () => {
  it('puts the page first, because that is what a narrow tab shows', () => {
    expect(pageTitle('Services')).toBe('Services · Kanea')
  })
})
