import { beforeEach, vi } from 'vitest'

/**
 * uPlot draws on a canvas 2d context, which jsdom does not provide: any test
 * that renders Overview or ServiceDetail would crash on the real library. The
 * mock records the calls UPlotChart makes so its lifecycle (create, setData,
 * setSize, destroy) is assertable; everything visual is out of scope for
 * jsdom and covered instead by the pure helpers in lib/uplot.ts.
 */
vi.mock('uplot', () => {
  class FakeUPlot {
    static instances: FakeUPlot[] = []
    // The path builders UPlotChart reaches for (spline). A factory returning
    // a no-op builder is enough: nothing draws in jsdom.
    static paths = { spline: () => () => null }
    opts: unknown
    data: unknown
    sizes: unknown[] = []
    destroyed = false
    root = document.createElement('div')

    constructor(opts: unknown, data: unknown, target?: HTMLElement) {
      this.opts = opts
      this.data = data
      target?.appendChild(this.root)
      FakeUPlot.instances.push(this)
    }

    setData(data: unknown) {
      this.data = data
    }

    setSize(size: unknown) {
      this.sizes.push(size)
    }

    destroy() {
      this.destroyed = true
      this.root.remove()
    }
  }
  return { default: FakeUPlot }
})

/**
 * localStorage, defined once for every test file. Node's own globals shadow
 * jsdom's, so it does not exist in this environment even though every browser
 * has it, and useTheme reads it on mount and writes it in an effect.
 *
 * It is *defined* here rather than stubbed per test, and that is the whole
 * point: `vi.unstubAllGlobals()` in an afterEach restores a stubbed global to
 * what it was, which here is `undefined`. A passive effect flushing after a
 * test's teardown then calls setItem on nothing, which fails one run in
 * dozens and passes every rerun; it reddened a dashboard gate before it was
 * understood. A definition survives unstubbing, so the window a component
 * sees is the same one whatever order the hooks run in. Isolation comes from
 * clearing the store between tests instead.
 */
class MemoryStorage implements Storage {
  private store = new Map<string, string>()

  get length(): number {
    return this.store.size
  }

  key(index: number): string | null {
    return [...this.store.keys()][index] ?? null
  }

  getItem(key: string): string | null {
    return this.store.get(key) ?? null
  }

  setItem(key: string, value: string): void {
    this.store.set(key, String(value))
  }

  removeItem(key: string): void {
    this.store.delete(key)
  }

  clear(): void {
    this.store.clear()
  }
}

const memoryStorage = new MemoryStorage()
Object.defineProperty(window, 'localStorage', {
  value: memoryStorage,
  configurable: true,
  writable: true,
})

beforeEach(() => {
  memoryStorage.clear()
})
