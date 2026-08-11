import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, Label } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import {
  createToken,
  deleteUser,
  fetchTokens,
  fetchUsers,
  putUser,
  revokeToken,
  type TokenCreated,
} from '@/lib/api'
import { timeOrNever } from '@/lib/settings'
import { relativeAge } from '@/lib/state'

type Role = 'admin' | 'viewer'

/**
 * AccountsSection manages users and bearer tokens (PRD §13.2, §13.3).
 *
 * A token's secret exists exactly once, in the creation response — the store
 * keeps only a hash, so the banner under the create form is the only place it
 * will ever be readable. The password field is controlled state only for as
 * long as the form is open, and is cleared the moment the PUT succeeds.
 */
export function AccountsSection({
  csrf,
  canWrite,
  self,
}: {
  csrf: string | undefined
  canWrite: boolean
  /** self is the signed-in subject; deleting yourself is greyed out. */
  self: string | undefined
}) {
  const client = useQueryClient()
  const [error, setError] = useState('')

  const users = useQuery({ queryKey: ['users'], queryFn: ({ signal }) => fetchUsers(signal) })
  const tokens = useQuery({ queryKey: ['tokens'], queryFn: ({ signal }) => fetchTokens(signal) })

  // User form.
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('viewer')
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)

  const saveUser = useMutation({
    mutationFn: () => putUser(name.trim(), password, role, csrf),
    onSuccess: () => {
      setError('')
      // The plaintext has done its job; nothing keeps it a moment longer.
      setPassword('')
      setName('')
      void client.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  const removeUser = useMutation({
    mutationFn: (user: string) => deleteUser(user, csrf),
    onSuccess: () => {
      setError('')
      void client.invalidateQueries({ queryKey: ['users'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  // Token form.
  const [tokenName, setTokenName] = useState('')
  const [tokenRole, setTokenRole] = useState<Role>('viewer')
  const [expiresIn, setExpiresIn] = useState('720h')
  const [minted, setMinted] = useState<TokenCreated | null>(null)
  const [copied, setCopied] = useState(false)
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null)

  const mint = useMutation({
    mutationFn: () => {
      const req: { name: string; role: Role; expires_in?: string } = {
        name: tokenName.trim(),
        role: tokenRole,
      }
      if (expiresIn.trim() !== '') req.expires_in = expiresIn.trim()
      return createToken(req, csrf)
    },
    onSuccess: (created) => {
      setError('')
      setMinted(created)
      setCopied(false)
      setTokenName('')
      void client.invalidateQueries({ queryKey: ['tokens'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  const revoke = useMutation({
    mutationFn: (id: string) => revokeToken(id, csrf),
    onSuccess: () => {
      setError('')
      void client.invalidateQueries({ queryKey: ['tokens'] })
    },
    onError: (err: Error) => setError(err.message),
  })

  return (
    <section className="space-y-3">
      <h2 className="text-lg font-semibold tracking-tight">Accounts</h2>

      {error ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
          {error}
        </p>
      ) : null}

      <Card className="py-2">
        <Table>
          <THead>
            <tr>
              <TH className="pt-2">User</TH>
              <TH className="pt-2">Role</TH>
              <TH className="pt-2">Created</TH>
              <TH className="pt-2">Updated</TH>
              {canWrite ? <TH className="pt-2 text-right">Remove</TH> : null}
            </tr>
          </THead>
          <TBody>
            {(users.data ?? []).map((u) => {
              const isSelf = u.name === self
              return (
                <TR key={u.name}>
                  <TD className="font-mono text-xs">{u.name}</TD>
                  <TD>
                    <Badge variant={u.role === 'admin' ? 'accent' : 'muted'}>{u.role}</Badge>
                  </TD>
                  <TD className="font-mono text-xs text-muted-foreground">
                    {timeOrNever(u.created)}
                  </TD>
                  <TD className="font-mono text-xs text-muted-foreground">
                    {timeOrNever(u.updated)}
                  </TD>
                  {canWrite ? (
                    <TD className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        className={`h-7 px-2 text-xs ${
                          confirmDelete === u.name ? 'border-status-warn text-status-warn' : ''
                        }`}
                        disabled={isSelf || removeUser.isPending}
                        title={
                          isSelf
                            ? 'You cannot delete the account you are signed in with.'
                            : undefined
                        }
                        onClick={() => {
                          if (confirmDelete !== u.name) {
                            setConfirmDelete(u.name)
                            return
                          }
                          setConfirmDelete(null)
                          removeUser.mutate(u.name)
                        }}
                      >
                        {confirmDelete === u.name ? 'Confirm delete?' : 'Delete'}
                      </Button>
                    </TD>
                  ) : null}
                </TR>
              )
            })}
          </TBody>
        </Table>
        {users.isError ? (
          <p className="px-4 pb-2 text-sm text-destructive">Cannot read the account list.</p>
        ) : null}
      </Card>

      {canWrite ? (
        <Card>
          <CardHeader>
            <CardTitle>Create or replace an account</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap items-end gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="account-name">Name</Label>
              <Input
                id="account-name"
                className="w-44 font-mono"
                autoComplete="off"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="account-password">Password</Label>
              <Input
                id="account-password"
                type="password"
                className="w-44"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="account-role">Role</Label>
              <Select
                id="account-role"
                className="w-32"
                value={role}
                onChange={(e) => setRole(e.target.value as Role)}
              >
                <option value="viewer">viewer</option>
                <option value="admin">admin</option>
              </Select>
            </div>
            <Button
              disabled={saveUser.isPending || name.trim() === '' || password === ''}
              onClick={() => saveUser.mutate()}
            >
              {saveUser.isPending ? 'Saving…' : 'Save account'}
            </Button>
            <p className="w-full text-xs text-muted-foreground">
              Writing an existing name replaces its password and role.
            </p>
          </CardContent>
        </Card>
      ) : null}

      <h3 className="pt-2 text-base font-semibold tracking-tight">API tokens</h3>

      <Card className="py-2">
        <Table>
          <THead>
            <tr>
              <TH className="pt-2">Token</TH>
              <TH className="pt-2">Role</TH>
              <TH className="pt-2">Created</TH>
              <TH className="pt-2">Expires</TH>
              <TH className="pt-2">Last used</TH>
              {canWrite ? <TH className="pt-2 text-right">Revoke</TH> : null}
            </tr>
          </THead>
          <TBody>
            {(tokens.data ?? []).map((t) => (
              <TR key={t.id}>
                <TD>
                  <span className="block font-mono text-xs">{t.name}</span>
                  <span className="block font-mono text-[11px] text-muted-foreground">{t.id}</span>
                </TD>
                <TD>
                  <Badge variant={t.role === 'admin' ? 'accent' : 'muted'}>{t.role}</Badge>
                </TD>
                <TD className="font-mono text-xs text-muted-foreground">{relativeAge(t.created)}</TD>
                <TD className="font-mono text-xs text-muted-foreground">
                  {timeOrNever(t.expires)}
                </TD>
                <TD className="font-mono text-xs text-muted-foreground">
                  {timeOrNever(t.last_used)}
                </TD>
                {canWrite ? (
                  <TD className="text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      className={`h-7 px-2 text-xs ${
                        confirmRevoke === t.id ? 'border-status-warn text-status-warn' : ''
                      }`}
                      disabled={revoke.isPending}
                      onClick={() => {
                        if (confirmRevoke !== t.id) {
                          setConfirmRevoke(t.id)
                          return
                        }
                        setConfirmRevoke(null)
                        revoke.mutate(t.id)
                      }}
                    >
                      {confirmRevoke === t.id ? 'Confirm revoke?' : 'Revoke'}
                    </Button>
                  </TD>
                ) : null}
              </TR>
            ))}
          </TBody>
        </Table>
        {tokens.isSuccess && (tokens.data ?? []).length === 0 ? (
          <p className="px-4 pb-2 text-sm text-muted-foreground">No tokens.</p>
        ) : null}
        {tokens.isError ? (
          <p className="px-4 pb-2 text-sm text-destructive">Cannot read the token list.</p>
        ) : null}
      </Card>

      {canWrite ? (
        <Card>
          <CardHeader>
            <CardTitle>Mint a token</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap items-end gap-3">
              <div className="space-y-1.5">
                <Label htmlFor="token-name">Name</Label>
                <Input
                  id="token-name"
                  className="w-44 font-mono"
                  placeholder="ci"
                  value={tokenName}
                  onChange={(e) => setTokenName(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="token-role">Role</Label>
                <Select
                  id="token-role"
                  className="w-32"
                  value={tokenRole}
                  onChange={(e) => setTokenRole(e.target.value as Role)}
                >
                  <option value="viewer">viewer</option>
                  <option value="admin">admin</option>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="token-expires">Expires in</Label>
                <Input
                  id="token-expires"
                  className="w-32 font-mono"
                  placeholder="720h"
                  value={expiresIn}
                  onChange={(e) => setExpiresIn(e.target.value)}
                />
              </div>
              <Button
                disabled={mint.isPending || tokenName.trim() === ''}
                onClick={() => mint.mutate()}
              >
                {mint.isPending ? 'Minting…' : 'Mint token'}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              A Go duration (<code className="font-mono">720h</code> is thirty days). Empty means
              the token never expires, which the daemon allows and warns about.
            </p>

            {minted ? (
              <div className="space-y-2 rounded-md border border-status-warn/40 bg-status-warn/10 px-3 py-2">
                <p className="text-sm">
                  Token <span className="font-mono">{minted.token.name}</span> (
                  <span className="font-mono">{minted.token.id}</span>) minted. This secret is
                  shown once and is not recoverable — copy it now.
                </p>
                <div className="flex items-center gap-2">
                  <Input
                    readOnly
                    className="font-mono text-xs"
                    aria-label="Token secret"
                    value={minted.secret}
                    onFocus={(e) => e.target.select()}
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      void navigator.clipboard?.writeText(minted.secret).then(() => setCopied(true))
                    }}
                  >
                    {copied ? 'Copied' : 'Copy'}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setMinted(null)}>
                    Dismiss
                  </Button>
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </section>
  )
}
