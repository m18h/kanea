import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { Router } from '@/lib/router'
import { SessionContext, type SessionState } from '@/lib/session-context'
import { ServiceActions } from '@/pages/ServiceDetail'
import { scaleBounds } from '@/lib/scale'
import type { RolloutStatus, } from '@/lib/rollout'
import type { Service } from '@/lib/api'

const service = {
  Project: 'shop',
  Service: 'web',
  Count: 2,
  Image: 'img:1',
  Resources: {},
} as Service

const adminSession: SessionState = {
  session: { subject: 'admin', role: 'admin', via: 'session' },
  loading: false,
  csrf: 'token',
  signIn: vi.fn(),
  signOut: vi.fn(),
}

function renderActions(
  rollout: RolloutStatus,
  session: SessionState = adminSession,
  desired: Service = service,
) {
  return render(
    <SessionContext.Provider value={session}>
      <Router>
        <ServiceActions project="shop" service="web" desired={desired} rollout={rollout} />
      </Router>
    </SessionContext.Provider>,
  )
}

/** withScaling returns the fixture at a count, optionally autoscaled. */
function withScaling(count: number, scaling?: Service['Scaling']): Service {
  return { ...service, Count: count, ...(scaling ? { Scaling: scaling } : {}) }
}

describe('ServiceActions', () => {
  it('idle: lifecycle buttons are enabled and no status line shows', () => {
    renderActions({ deploying: false, updated: 2, total: 2 })
    expect(screen.getByRole('button', { name: /Restart/ })).toHaveProperty('disabled', false)
    expect(screen.queryByText(/rolling out/)).toBeNull()
  })

  it('deploying: buttons lock and the rollout line reports progress', () => {
    renderActions({ deploying: true, updated: 1, total: 3 })
    expect(screen.getByText('rolling out · 1/3 updated')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Restart/ })).toHaveProperty('disabled', true)
    expect(screen.getByRole('button', { name: /Stop/ })).toHaveProperty('disabled', true)
    // Edit spec stays reachable: reading a spec during a rollout is harmless.
    expect(screen.getByRole('button', { name: /Edit spec/ })).toHaveProperty('disabled', false)
  })

  it('a viewer gets disabled buttons whatever the rollout says', () => {
    renderActions(
      { deploying: false, updated: 2, total: 2 },
      { ...adminSession, session: { subject: 'v', role: 'viewer', via: 'session' } },
    )
    expect(screen.getByRole('button', { name: /Restart/ })).toHaveProperty('disabled', true)
  })
})

/**
 * Scaling from the detail page: a Scale button that opens a dialog.
 *
 * The rule under test is not "does a click fire a request" but "does the
 * picker stop where the daemon would refuse". `handleScale` in internal/api
 * answers an out-of-range count with 409 rather than clamping it, so a control
 * that offered the click would be handing the operator a guaranteed failure.
 *
 * And nothing is written while the dialog is open: a replica count is a
 * decision, so the draft stays local until Scale is pressed.
 */
describe('ServiceActions scaling', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  function captureScale(): { url: string; body: string }[] {
    const calls: { url: string; body: string }[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((url: string | URL | Request, init?: RequestInit) => {
        const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url
        // apiFetch sends a JSON string body; anything else is not a scale.
        calls.push({ url: href, body: typeof init?.body === 'string' ? init.body : '' })
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) } as Response)
      }),
    )
    return calls
  }

  /** openScale clicks the toolbar button and returns the dialog's controls. */
  function openScale() {
    fireEvent.click(screen.getByRole('button', { name: /Scale$/ }))
    return {
      more: screen.getByRole('button', { name: 'More replicas' }),
      fewer: screen.getByRole('button', { name: 'Fewer replicas' }),
      readout: screen.getByRole('status'),
    }
  }

  it('opens a dialog and writes nothing until Scale is pressed', () => {
    const calls = captureScale()
    renderActions({ deploying: false, updated: 2, total: 2 }, adminSession, withScaling(2))

    const { more, readout } = openScale()
    expect(readout.textContent).toBe('2')
    fireEvent.click(more)
    fireEvent.click(more)
    expect(readout.textContent).toBe('4')
    // Two clicks on the picker, and production is untouched.
    expect(calls).toHaveLength(0)

    fireEvent.click(screen.getByRole('button', { name: 'Scale to 4' }))
    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toContain('/v1/services/shop/web/scale')
    expect(calls[0]?.body).toContain('"count":4')
  })

  it('refuses to submit an unchanged count', () => {
    renderActions({ deploying: false, updated: 3, total: 3 }, adminSession, withScaling(3))
    const { more } = openScale()
    // The submit names the decision it commits, so it is distinguishable from
    // the toolbar button that opened the dialog.
    expect(screen.getByRole('button', { name: 'Scale to 3' })).toHaveProperty('disabled', true)
    fireEvent.click(more)
    expect(screen.getByRole('button', { name: 'Scale to 4' })).toHaveProperty('disabled', false)
  })

  it('will not go below one: zero is a stop, and Stop owns it', () => {
    renderActions({ deploying: false, updated: 1, total: 1 }, adminSession, withScaling(1))
    const { fewer } = openScale()
    expect(fewer).toHaveProperty('disabled', true)
    expect(screen.getByText(/Scaling to zero is stopping/)).toBeTruthy()
  })

  it('stops at the autoscale ceiling the daemon would refuse past', () => {
    const scaling = { min: 2, max: 4, metrics: [{ name: 'cpu', target: 70 }] }
    renderActions({ deploying: false, updated: 4, total: 4 }, adminSession, withScaling(4, scaling))
    const { more, fewer } = openScale()
    expect(more).toHaveProperty('disabled', true)
    expect(fewer).toHaveProperty('disabled', false)
    // The range is stated, not just enforced.
    expect(screen.getByText(/allowed/)).toBeTruthy()
  })

  it('stops at the autoscale floor as well, and says what the autoscaler will do', () => {
    const scaling = { min: 2, max: 4, metrics: [{ name: 'cpu', target: 70 }] }
    renderActions({ deploying: false, updated: 2, total: 2 }, adminSession, withScaling(2, scaling))
    const { fewer } = openScale()
    expect(fewer).toHaveProperty('disabled', true)
    expect(screen.getByText(/until the next autoscale decision/)).toBeTruthy()
  })

  // The case that decides whether this control is usable on an autoscaling
  // service: its count moves every few seconds, and re-seeding the draft from
  // it would wipe the operator's choice, over and over.
  it('keeps the chosen count when the live count moves underneath it', () => {
    const view = renderActions(
      { deploying: false, updated: 3, total: 3 },
      adminSession,
      withScaling(3, { min: 2, max: 10, metrics: [{ name: 'cpu', target: 70 }] }),
    )
    const { more, readout } = openScale()
    fireEvent.click(more)
    fireEvent.click(more)
    expect(readout.textContent).toBe('5')

    // The autoscaler moves 3 -> 4 while the dialog is open.
    view.rerender(
      <SessionContext.Provider value={adminSession}>
        <Router>
          <ServiceActions
            project="shop"
            service="web"
            desired={withScaling(4, { min: 2, max: 10, metrics: [{ name: 'cpu', target: 70 }] })}
            rollout={{ deploying: false, updated: 4, total: 4 }}
          />
        </Router>
      </SessionContext.Provider>,
    )

    expect(screen.getByRole('button', { name: 'Scale to 5' })).toHaveProperty('disabled', false)
    expect(screen.getByText(/Currently/).textContent).toContain('4')
  })

  it('a viewer cannot open the dialog at all', () => {
    renderActions(
      { deploying: false, updated: 2, total: 2 },
      { ...adminSession, session: { subject: 'v', role: 'viewer', via: 'session' } },
      withScaling(2),
    )
    expect(screen.getByRole('button', { name: /Scale$/ })).toHaveProperty('disabled', true)
  })
})

/**
 * The bound rule itself, pinned against internal/api's `handleScale`.
 *
 * Both halves of its condition matter and neither is redundant: a policy
 * bounds a manual scale only when it declares a max AND at least one metric,
 * because a policy with no metric can never fire and must not pin a service to
 * a range nothing enforces. If the daemon's condition changes, this fails.
 */
describe('scaleBounds', () => {
  it('leaves a service with no policy unbounded above, floored at one', () => {
    const b = scaleBounds(withScaling(3))
    expect(b.min).toBe(1)
    expect(b.max).toBe(Number.POSITIVE_INFINITY)
    expect(b.hint).toBeUndefined()
  })

  it('bounds a policy that has a max and a metric', () => {
    const b = scaleBounds(withScaling(3, { min: 2, max: 6, metrics: [{ name: 'rps', target: 500 }] }))
    expect(b.min).toBe(2)
    expect(b.max).toBe(6)
    expect(b.hint).toContain('between 2 and 6')
  })

  it('does not bound a policy with no metrics: it can never fire', () => {
    const b = scaleBounds(withScaling(3, { min: 2, max: 6, metrics: [] }))
    expect(b.max).toBe(Number.POSITIVE_INFINITY)
  })

  it('does not bound a policy with no max', () => {
    const b = scaleBounds(withScaling(3, { min: 2, max: 0, metrics: [{ name: 'cpu', target: 70 }] }))
    expect(b.max).toBe(Number.POSITIVE_INFINITY)
  })

  it('never floors below one, whatever the policy says', () => {
    const b = scaleBounds(withScaling(1, { min: 0, max: 6, metrics: [{ name: 'cpu', target: 70 }] }))
    expect(b.min).toBe(1)
  })
})
