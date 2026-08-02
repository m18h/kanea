import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input, Label } from '@/components/ui/input'
import { useSession } from '@/hooks/useSession'
import { login } from '@/lib/session'

/**
 * The login screen (PRD §13.2, basic auth).
 *
 * It is the whole app until someone signs in: there is no read-only preview,
 * because every route behind it is deny-by-default at the daemon and would
 * render as a wall of errors rather than as a page.
 */
export function Login() {
  const { signIn } = useSession()
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
      // Whatever the daemon says, verbatim — it is deliberately vague about
      // which half was wrong (§14, A07), and paraphrasing it here would only
      // risk making it more specific than it means to be.
      setError(err instanceof Error ? err.message : 'sign in failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="text-base">Sign in to Kanea</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-1.5">
              <Label htmlFor="user">User</Label>
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

            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
