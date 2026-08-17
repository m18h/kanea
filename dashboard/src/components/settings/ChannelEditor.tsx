import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input, Label } from '@/components/ui/input'
import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import type { ChannelForms } from '@/lib/settings'

/**
 * ChannelEditor is the one channel form, used for the node defaults and for
 * each project override: same fields, same rules, so the two cannot drift.
 *
 * Every credential field takes a `secret:` reference, never a value: the
 * record is readable back over the API, and a reference is safe to read back
 * (constraint #4).
 */
export function ChannelEditor({
  value,
  onChange,
  disabled,
  idPrefix,
}: {
  value: ChannelForms
  onChange: (next: ChannelForms) => void
  disabled: boolean
  /** idPrefix keeps label/input ids unique when two editors are on screen. */
  idPrefix: string
}) {
  const set = (patch: Partial<ChannelForms>) => onChange({ ...value, ...patch })
  const id = (suffix: string) => `${idPrefix}-${suffix}`

  return (
    <div className="space-y-3">
      <ChannelCard
        title="Telegram"
        enabled={value.telegram.enabled}
        onToggle={(on) => set({ telegram: { ...value.telegram, enabled: on } })}
        disabled={disabled}
      >
        <Field id={id('tg-chat')} label="Chat id">
          <Input
            id={id('tg-chat')}
            className="font-mono"
            disabled={disabled}
            value={value.telegram.chatId}
            onChange={(e) => set({ telegram: { ...value.telegram, chatId: e.target.value } })}
          />
        </Field>
        <Field id={id('tg-token')} label="Bot token reference" refHint>
          <Input
            id={id('tg-token')}
            className="font-mono"
            placeholder="secret:shared/telegram-bot"
            disabled={disabled}
            value={value.telegram.tokenRef}
            onChange={(e) => set({ telegram: { ...value.telegram, tokenRef: e.target.value } })}
          />
        </Field>
      </ChannelCard>

      <ChannelCard
        title="Webhook"
        enabled={value.webhook.enabled}
        onToggle={(on) => set({ webhook: { ...value.webhook, enabled: on } })}
        disabled={disabled}
      >
        <Field id={id('wh-url')} label="URL">
          <Input
            id={id('wh-url')}
            className="font-mono"
            placeholder="https://example.com/hook"
            disabled={disabled}
            value={value.webhook.url}
            onChange={(e) => set({ webhook: { ...value.webhook, url: e.target.value } })}
          />
        </Field>
        <Field id={id('wh-secret')} label="Signing secret reference" refHint>
          <Input
            id={id('wh-secret')}
            className="font-mono"
            placeholder="secret:shared/webhook-hmac"
            disabled={disabled}
            value={value.webhook.secretRef}
            onChange={(e) => set({ webhook: { ...value.webhook, secretRef: e.target.value } })}
          />
        </Field>
      </ChannelCard>

      <ChannelCard
        title="Slack / Discord"
        enabled={value.slack.enabled}
        onToggle={(on) => set({ slack: { ...value.slack, enabled: on } })}
        disabled={disabled}
      >
        <Field id={id('slack-url')} label="Incoming webhook URL reference" refHint>
          <Input
            id={id('slack-url')}
            className="font-mono"
            placeholder="secret:shared/slack-webhook"
            disabled={disabled}
            value={value.slack.urlRef}
            onChange={(e) => set({ slack: { ...value.slack, urlRef: e.target.value } })}
          />
        </Field>
      </ChannelCard>

      <ChannelCard
        title="ntfy"
        enabled={value.ntfy.enabled}
        onToggle={(on) => set({ ntfy: { ...value.ntfy, enabled: on } })}
        disabled={disabled}
      >
        <Field id={id('ntfy-url')} label="Topic URL">
          <Input
            id={id('ntfy-url')}
            className="font-mono"
            placeholder="https://ntfy.sh/kanea"
            disabled={disabled}
            value={value.ntfy.url}
            onChange={(e) => set({ ntfy: { ...value.ntfy, url: e.target.value } })}
          />
        </Field>
        <Field id={id('ntfy-token')} label="Token reference" refHint>
          <Input
            id={id('ntfy-token')}
            className="font-mono"
            placeholder="secret:shared/ntfy-token"
            disabled={disabled}
            value={value.ntfy.tokenRef}
            onChange={(e) => set({ ntfy: { ...value.ntfy, tokenRef: e.target.value } })}
          />
        </Field>
      </ChannelCard>

      <ChannelCard
        title="Email (SMTP)"
        enabled={value.smtp.enabled}
        onToggle={(on) => set({ smtp: { ...value.smtp, enabled: on } })}
        disabled={disabled}
      >
        <Field id={id('smtp-host')} label="Host">
          <Input
            id={id('smtp-host')}
            className="font-mono"
            disabled={disabled}
            value={value.smtp.host}
            onChange={(e) => set({ smtp: { ...value.smtp, host: e.target.value } })}
          />
        </Field>
        <Field id={id('smtp-port')} label="Port">
          <Input
            id={id('smtp-port')}
            className="font-mono"
            placeholder="587"
            disabled={disabled}
            value={value.smtp.port}
            onChange={(e) => set({ smtp: { ...value.smtp, port: e.target.value } })}
          />
        </Field>
        <Field id={id('smtp-from')} label="From">
          <Input
            id={id('smtp-from')}
            className="font-mono"
            disabled={disabled}
            value={value.smtp.from}
            onChange={(e) => set({ smtp: { ...value.smtp, from: e.target.value } })}
          />
        </Field>
        <Field id={id('smtp-to')} label="To (comma separated)">
          <Input
            id={id('smtp-to')}
            className="font-mono"
            disabled={disabled}
            value={value.smtp.to}
            onChange={(e) => set({ smtp: { ...value.smtp, to: e.target.value } })}
          />
        </Field>
        <Field id={id('smtp-user')} label="Username">
          <Input
            id={id('smtp-user')}
            className="font-mono"
            disabled={disabled}
            value={value.smtp.username}
            onChange={(e) => set({ smtp: { ...value.smtp, username: e.target.value } })}
          />
        </Field>
        <Field id={id('smtp-pass')} label="Password reference" refHint>
          <Input
            id={id('smtp-pass')}
            className="font-mono"
            placeholder="secret:shared/smtp-password"
            disabled={disabled}
            value={value.smtp.passwordRef}
            onChange={(e) => set({ smtp: { ...value.smtp, passwordRef: e.target.value } })}
          />
        </Field>
      </ChannelCard>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field id={id('on')} label="Send on (patterns, comma or space separated)">
          <Input
            id={id('on')}
            className="font-mono"
            placeholder="deploy.* *.failed backup.*"
            disabled={disabled}
            value={value.on}
            onChange={(e) => set({ on: e.target.value })}
          />
        </Field>
        <Field id={id('severity')} label="Severity floor">
          <Select
            id={id('severity')}
            disabled={disabled}
            value={value.severity}
            onChange={(e) => set({ severity: e.target.value })}
          >
            <option value="">default (info)</option>
            <option value="info">info</option>
            <option value="warning">warning</option>
            <option value="error">error</option>
          </Select>
        </Field>
      </div>
    </div>
  )
}

function ChannelCard({
  title,
  enabled,
  onToggle,
  disabled,
  children,
}: {
  title: string
  enabled: boolean
  onToggle: (on: boolean) => void
  disabled: boolean
  children: React.ReactNode
}) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between space-y-0">
        <CardTitle>{title}</CardTitle>
        <Switch
          checked={enabled}
          onCheckedChange={onToggle}
          disabled={disabled}
          aria-label={`Enable ${title}`}
        />
      </CardHeader>
      {enabled ? (
        <CardContent className="grid gap-3 sm:grid-cols-2">{children}</CardContent>
      ) : null}
    </Card>
  )
}

function Field({
  id,
  label,
  refHint,
  children,
}: {
  id: string
  label: string
  refHint?: boolean
  children: React.ReactNode
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {refHint ? (
        <p className="text-xs text-muted-foreground">
          A <code className="font-mono">secret:</code> reference, never the value itself.
        </p>
      ) : null}
    </div>
  )
}
