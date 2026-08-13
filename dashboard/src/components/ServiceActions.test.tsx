import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { Router } from '@/lib/router'
import { SessionContext, type SessionState } from '@/lib/session-context'
import { ServiceActions } from '@/pages/ServiceDetail'
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

function renderActions(rollout: RolloutStatus, session: SessionState = adminSession) {
  return render(
    <SessionContext.Provider value={session}>
      <Router>
        <ServiceActions project="shop" service="web" desired={service} rollout={rollout} />
      </Router>
    </SessionContext.Provider>,
  )
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
