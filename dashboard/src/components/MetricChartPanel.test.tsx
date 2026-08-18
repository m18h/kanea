import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import uPlot from 'uplot'
import { MetricChartPanel } from './MetricChartPanel'

// The fake from test/setup.ts, with its recording surface.
const Fake = uPlot as unknown as {
  instances: Array<{ data: unknown; destroyed: boolean }>
}

const empty = { times: [], values: [] }

beforeEach(() => {
  Fake.instances.length = 0
})

describe('MetricChartPanel', () => {
  it('draws a skeleton and no chart while the data is still arriving', () => {
    // The whole point of the status prop. This panel used to print "no data"
    // for the entire duration of the seed request, which reads as broken where
    // the truth was coming.
    render(
      <MetricChartPanel label="CPU" unit="%" series={empty} scale="percent" tone={1} status="loading" />,
    )

    expect(screen.queryByText('no samples yet')).toBeNull()
    expect(Fake.instances).toHaveLength(0)
  })

  it('says "no samples yet" once there is genuinely nothing recorded', () => {
    // "yet" locates the absence in the record rather than the value, which is
    // also the honest thing to say for the ten seconds after a daemon restart.
    render(
      <MetricChartPanel label="CPU" unit="%" series={empty} scale="percent" tone={1} status="empty" />,
    )

    expect(screen.getByText('no samples yet')).toBeTruthy()
    expect(Fake.instances).toHaveLength(0)
  })

  it('shows an error instead of an empty state', () => {
    render(
      <MetricChartPanel
        label="CPU"
        unit="%"
        series={empty}
        scale="percent"
        tone={1}
        status="error"
        error="the daemon said no"
      />,
    )

    expect(screen.getByText('the daemon said no')).toBeTruthy()
  })

  it('never renders a zero it did not measure', () => {
    // §9.2 at the one place it is easiest to break: a skeleton stands where a
    // chart goes, never where a number goes, and the readout stays a dash.
    const { container } = render(
      <MetricChartPanel label="CPU" unit="%" series={empty} scale="percent" tone={1} status="loading" />,
    )

    expect(container.textContent).not.toContain('0')
    expect(screen.getByText('-')).toBeTruthy()
  })

  it('draws the chart whenever there are points, whatever the status says', () => {
    // A series with data is never explained away: status only covers absence.
    render(
      <MetricChartPanel
        label="CPU"
        unit="%"
        series={{ times: [1, 2], values: [10, 20] }}
        scale="percent"
        tone={1}
        status="loading"
      />,
    )

    expect(Fake.instances).toHaveLength(1)
    expect(screen.queryByText('no samples yet')).toBeNull()
  })

  it('defaults to drawing, so a caller with nothing to say gets the old behaviour', () => {
    render(
      <MetricChartPanel
        label="CPU"
        unit="%"
        series={{ times: [1], values: [10] }}
        scale="percent"
        tone={1}
      />,
    )

    expect(Fake.instances).toHaveLength(1)
  })
})
