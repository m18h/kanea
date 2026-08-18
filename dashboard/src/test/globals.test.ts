import { expect, it, vi } from 'vitest'

/**
 * The environment's own contract, pinned. Both of these held only by accident
 * before setup.ts defined localStorage: the theme effect writes storage, and
 * a test file that stubbed it handed the next flushed effect an `undefined`
 * global the moment its afterEach unstubbed. That failure lands in whichever
 * test happens to be running, which is why it reads as an unrelated flake.
 */
it('storage outlives a test that unstubs every global', () => {
  vi.stubGlobal('localStorage', {
    getItem: () => null,
    setItem: () => {},
    removeItem: () => {},
  })
  vi.unstubAllGlobals()

  expect(window.localStorage).toBeDefined()
  expect(() => window.localStorage.setItem('kanea-theme', 'dark')).not.toThrow()
})

it('storage is empty at the start of a test, whatever the last one wrote', () => {
  expect(window.localStorage.getItem('kanea-theme')).toBeNull()
  window.localStorage.setItem('kanea-theme', 'light')
  expect(window.localStorage.getItem('kanea-theme')).toBe('light')
})
