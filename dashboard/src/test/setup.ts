import { vi } from 'vitest'

/**
 * uPlot draws on a canvas 2d context, which jsdom does not provide — any test
 * that renders Overview or ServiceDetail would crash on the real library. The
 * mock records the calls UPlotChart makes so its lifecycle (create, setData,
 * setSize, destroy) is assertable; everything visual is out of scope for
 * jsdom and covered instead by the pure helpers in lib/uplot.ts.
 */
vi.mock('uplot', () => {
  class FakeUPlot {
    static instances: FakeUPlot[] = []
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
