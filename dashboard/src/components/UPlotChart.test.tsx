import { describe, expect, it } from 'vitest'
import { render } from '@testing-library/react'
import uPlot from 'uplot'
import { UPlotChart } from './UPlotChart'

// The fake from test/setup.ts, with its recording surface.
const Fake = uPlot as unknown as {
  instances: Array<{ data: unknown; destroyed: boolean }>
}

function lastInstance() {
  const inst = Fake.instances.at(-1)
  if (!inst) throw new Error('no uPlot instance was created')
  return inst
}

describe('UPlotChart', () => {
  it('creates one live instance and hands it the data', () => {
    render(
      <UPlotChart
        times={[1, 2, 3]}
        values={[10, null, 30]}
        unit="%"
        label="CPU"
        tone={1}
        scale="percent"
      />,
    )
    // StrictMode pairs create/destroy on the probe mount; the survivor is the
    // one that matters.
    const live = Fake.instances.filter((i) => !i.destroyed)
    expect(live).toHaveLength(1)
    // Values are display-smoothed, but a gap survives smoothing untouched:
    // and gap-adjacent points average only their own side, so this data is
    // its own fixed point.
    expect(live[0]?.data).toEqual([
      [1, 2, 3],
      [10, null, 30],
    ])
  })

  it('routes new samples through setData rather than recreating', () => {
    const { rerender } = render(
      <UPlotChart times={[1]} values={[10]} unit="%" label="CPU" tone={1} scale="percent" />,
    )
    const before = Fake.instances.filter((i) => !i.destroyed).length

    rerender(
      <UPlotChart times={[1, 2]} values={[10, 20]} unit="%" label="CPU" tone={1} scale="percent" />,
    )
    const after = Fake.instances.filter((i) => !i.destroyed)
    expect(after).toHaveLength(before)
    // setData received the new pair (values arrive display-smoothed).
    const data = lastInstance().data as [number[], (number | null)[]]
    expect(data[0]).toEqual([1, 2])
    expect(data[1]).toHaveLength(2)
  })

  it('destroys the instance on unmount', () => {
    const { unmount } = render(
      <UPlotChart times={[1]} values={[10]} unit="%" label="CPU" tone={1} scale="percent" />,
    )
    unmount()
    expect(Fake.instances.every((i) => i.destroyed)).toBe(true)
  })
})
