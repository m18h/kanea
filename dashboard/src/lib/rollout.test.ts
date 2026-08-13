import { describe, expect, it } from 'vitest'
import { rolloutStatus } from './rollout'
import type { Alloc, Service } from './api'

const HASH = 'sha256:new'
const OLD = 'sha256:old'

function svc(count: number, hash?: string): Service {
  return {
    Project: 'shop',
    Service: 'web',
    Count: count,
    Image: 'img:1',
    Resources: {},
    ...(hash !== undefined ? { spec_hash: hash } : {}),
  } as Service
}

function alloc(state: string, hash?: string): Alloc {
  return {
    id: 'a',
    project: 'shop',
    service: 'web',
    index: 0,
    state,
    ...(hash !== undefined ? { spec_hash: hash } : {}),
  }
}

describe('rolloutStatus', () => {
  it('everything at the desired hash is idle', () => {
    const r = rolloutStatus(svc(2, HASH), [alloc('running', HASH), alloc('running', HASH)])
    expect(r).toEqual({ deploying: false, updated: 2, total: 2 })
  })

  it('a stale alloc is a deploy in flight', () => {
    const r = rolloutStatus(svc(3, HASH), [
      alloc('running', HASH),
      alloc('running', HASH),
      alloc('running', OLD),
    ])
    expect(r.deploying).toBe(true)
    expect(r.updated).toBe(2)
    expect(r.total).toBe(3)
  })

  it('an empty-hash alloc is adopted, never stale', () => {
    // The AGENTS.md rule: a record with an empty hash is adopted, not rolled —
    // an upgrade of kanead must not read as a fleet-wide deploy.
    const r = rolloutStatus(svc(2, HASH), [alloc('running', ''), alloc('running', HASH)])
    expect(r.deploying).toBe(false)
    expect(r.updated).toBe(2)
  })

  it('a pending replacement at the new hash still counts as deploying', () => {
    // The window between an old alloc's teardown and its successor starting.
    const r = rolloutStatus(svc(1, HASH), [alloc('pending', HASH)])
    expect(r.deploying).toBe(true)
    expect(r.updated).toBe(0)
  })

  it('a crash-looping alloc at the new hash is NOT deploying', () => {
    // R29: restart is what clears a crash loop, so the state must not read
    // as a rollout that disables the restart button.
    const r = rolloutStatus(svc(1, HASH), [alloc('backoff', HASH)])
    expect(r.deploying).toBe(false)
  })

  it('no served hash (older daemon) never reports deploying', () => {
    const r = rolloutStatus(svc(2), [alloc('running', OLD), alloc('pending', OLD)])
    expect(r.deploying).toBe(false)
  })

  it('a stopped service is idle whatever its allocs say', () => {
    const r = rolloutStatus(svc(0, HASH), [alloc('running', OLD)])
    expect(r.deploying).toBe(false)
    expect(r.total).toBe(0)
  })
})
