import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Globe } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input, Label } from '@/components/ui/input'
import { Mark } from '@/components/Mark'
import { useSession } from '@/hooks/useSession'
import { login } from '@/lib/session'
import { fetchHealth } from '@/lib/api'

/**
 * The login screen (PRD §13.2, basic auth).
 *
 * It is the whole app until someone signs in: there is no read-only preview,
 * because every route behind it is deny-by-default at the daemon and would
 * render as a wall of errors rather than as a page.
 */
export function Login() {
  const { signIn } = useSession()
  // Health is public, so this is the one thing the app can ask before it has a
  // credential: including which sign-in methods exist.
  const health = useQuery({ queryKey: ['health'], queryFn: ({ signal }) => fetchHealth(signal) })
  const provider = health.data?.oidc?.enabled ? health.data.oidc : null
  // The daemon supplies the SSO entry point; only a path on its own origin is
  // ever rendered as a link. Anything else (an absolute URL, a javascript:
  // scheme) is a misconfiguration to ignore, not navigate to.
  const ssoPath = provider?.start_path?.startsWith('/') ? provider.start_path : null
  const [user, setUser] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  function onSubmit(event: React.FormEvent) {
    event.preventDefault()
    void submit()
  }

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      signIn(await login(user, password))
    } catch (err) {
      // Whatever the daemon says, verbatim: it is deliberately vague about
      // which half was wrong (§14, A07), and paraphrasing it here would only
      // risk making it more specific than it means to be.
      setError(err instanceof Error ? err.message : 'sign in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background px-4">
      <div className="mb-6 flex flex-col items-center gap-3">
        <Mark size={40} />
        <h1 className="text-lg font-semibold tracking-tight">Sign in to kanea</h1>
      </div>
      <Card className="w-full max-w-sm">
        <CardContent className="p-5">
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-1.5">
              <Label htmlFor="user">Username</Label>
              <Input
                id="user"
                name="username"
                autoComplete="username"
                autoFocus
                required
                value={user}
                onChange={(e) => setUser(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {error ? (
              // role=alert so a screen reader hears the refusal; the text is
              // escaped by React, as every daemon-supplied string is (§14 A03).
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            ) : null}

            <Button type="submit" className="w-full font-semibold" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>

          {ssoPath ? (
            <div className="mt-4 space-y-4">
              <div className="flex items-center gap-3">
                <span aria-hidden className="h-px flex-1 bg-border" />
                <span className="text-xs text-muted-foreground">or</span>
                <span aria-hidden className="h-px flex-1 bg-border" />
              </div>
              {/* A full navigation, not a fetch: the provider answers with a
                  redirect to its own login page, which only the browser can
                  follow. The daemon sets the handle cookie on the way out. */}
              <a
                href={ssoPath}
                className="flex h-9 w-full items-center justify-center gap-2 rounded-md border text-sm font-medium transition-colors hover:bg-muted"
              >
                <Globe size={15} aria-hidden />
                Continue with SSO
              </a>
              <p className="text-center text-xs text-muted-foreground">{issuerHost(provider?.issuer)}</p>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * issuerHost renders the provider as its host name.
 *
 * The daemon supplies this string, and React escapes it either way, but a
 * whole URL on a login screen reads like something to click, and this one is
 * not a link.
 */
function issuerHost(issuer: string | undefined): string {
  if (!issuer) return ''
  try {
    return new URL(issuer).host
  } catch {
    return issuer
  }
}
