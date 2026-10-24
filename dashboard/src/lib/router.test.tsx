import { beforeEach, describe, expect, it } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import { Router } from '@/lib/router'
import { useRouter } from '@/hooks/useRouter'

function Probe() {
  const { path, search } = useRouter()
  return <output>{`${path}|${search}`}</output>
}

/** A probe that can navigate, so a test drives the router the way a page does. */
function Driver({ onReady }: { onReady: (nav: ReturnType<typeof useRouter>['navigate']) => void }) {
  const { navigate } = useRouter()
  onReady(navigate)
  return <Probe />
}

describe('Router', () => {
  beforeEach(() => window.history.pushState({}, '', '/'))

  // The query used to be parsed off and thrown away, so a filtered link
  // rendered the unfiltered page.
  it('carries the query beside the path, not inside it', () => {
    let navigate: ReturnType<typeof useRouter>['navigate'] = () => {}
    render(
      <Router>
        <Driver onReady={(n) => (navigate = n)} />
      </Router>,
    )

    act(() => navigate('/services?q=api'))

    // Separate fields: matchPath counts '/' segments, so a path carrying the
    // query would match no route.
    expect(screen.getByRole('status').textContent).toBe('/services|?q=api')
    expect(window.location.search).toBe('?q=api')
  })

  it('re-renders on a popstate that only moves the query', () => {
    render(
      <Router>
        <Probe />
      </Router>,
    )

    window.history.pushState(null, '', '/services?q=web')
    // Dispatched rather than going through history.back(), which jsdom fires
    // asynchronously: this test is about the listener, not the timing.
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'))
    })

    expect(screen.getByRole('status').textContent).toBe('/services|?q=web')
  })

  // The rule the whole design rests on: filters replace, routes push, so Back
  // leaves the page instead of walking back through a half-typed word.
  it('replaces for a filter write, so Back skips every keystroke', async () => {
    let navigate: ReturnType<typeof useRouter>['navigate'] = () => {}
    render(
      <Router>
        <Driver onReady={(n) => (navigate = n)} />
      </Router>,
    )

    act(() => navigate('/services'))
    for (const q of ['a', 'ap', 'api']) {
      act(() => navigate(`/services?q=${q}`, { replace: true }))
    }
    expect(window.location.search).toBe('?q=api')

    act(() => window.history.back())

    await waitFor(() => expect(window.location.pathname).toBe('/'))
    expect(window.location.search).toBe('')
  })
})
