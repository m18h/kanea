import type { BackupSettingsRecord, WireNotifications } from './api'

/**
 * Pure helpers for the Settings page: the mapping between the wire's Go-named
 * notification channels and the forms, the backup form's shape checks, and the
 * zero-time handling account timestamps need.
 *
 * In lib rather than beside the page for the same reason backups.ts is: they
 * are pure, they are tested, and a component file that also exports functions
 * breaks fast refresh.
 */

// ---- time ----

/**
 * isZeroTime recognises Go's zero time.Time. `expires` and `last_used` on a
 * token cannot omit themselves (a struct field ignores omitempty), so "never"
 * arrives as year one rather than as absence.
 */
export function isZeroTime(iso: string | undefined): boolean {
  if (!iso) return true
  return iso.startsWith('0001-01-01')
}

/** timeOrNever renders a timestamp, or "never" for absence and the zero time. */
export function timeOrNever(iso: string | undefined): string {
  if (isZeroTime(iso)) return 'never'
  const at = new Date(iso as string)
  if (Number.isNaN(at.getTime())) return iso as string
  return at.toLocaleString()
}

// ---- notification channel forms ----

export interface ChannelForms {
  telegram: { enabled: boolean; chatId: string; tokenRef: string }
  webhook: { enabled: boolean; url: string; secretRef: string }
  slack: { enabled: boolean; urlRef: string }
  ntfy: { enabled: boolean; url: string; tokenRef: string }
  smtp: {
    enabled: boolean
    host: string
    port: string
    from: string
    to: string
    username: string
    passwordRef: string
  }
  /** on is the raw filter text; comma or whitespace separated glob patterns. */
  on: string
  /** severity floor: '' means the default (info). */
  severity: string
}

/** emptyChannelForms is the state for a node or project with nothing set. */
export function emptyChannelForms(): ChannelForms {
  return {
    telegram: { enabled: false, chatId: '', tokenRef: '' },
    webhook: { enabled: false, url: '', secretRef: '' },
    slack: { enabled: false, urlRef: '' },
    ntfy: { enabled: false, url: '', tokenRef: '' },
    smtp: { enabled: false, host: '', port: '', from: '', to: '', username: '', passwordRef: '' },
    on: '',
    severity: '',
  }
}

/** channelFormsFromWire seeds the editor from a stored record. */
export function channelFormsFromWire(n: WireNotifications | null | undefined): ChannelForms {
  const forms = emptyChannelForms()
  if (!n) return forms
  if (n.Telegram) {
    forms.telegram = {
      enabled: true,
      chatId: n.Telegram.ChatID ?? '',
      tokenRef: n.Telegram.TokenRef ?? '',
    }
  }
  if (n.Webhook) {
    forms.webhook = {
      enabled: true,
      url: n.Webhook.URL ?? '',
      secretRef: n.Webhook.SecretRef ?? '',
    }
  }
  if (n.Slack) {
    forms.slack = { enabled: true, urlRef: n.Slack.URLRef ?? '' }
  }
  if (n.Ntfy) {
    forms.ntfy = { enabled: true, url: n.Ntfy.URL ?? '', tokenRef: n.Ntfy.TokenRef ?? '' }
  }
  if (n.SMTP) {
    forms.smtp = {
      enabled: true,
      host: n.SMTP.Host ?? '',
      port: n.SMTP.Port ?? '',
      from: n.SMTP.From ?? '',
      to: (n.SMTP.To ?? []).join(', '),
      username: n.SMTP.Username ?? '',
      passwordRef: n.SMTP.PasswordRef ?? '',
    }
  }
  forms.on = (n.On ?? []).join(', ')
  forms.severity = n.Severity ?? ''
  return forms
}

/** splitPatterns turns the raw filter text into patterns: commas or spaces. */
export function splitPatterns(text: string): string[] {
  return text
    .split(/[\s,]+/)
    .map((p) => p.trim())
    .filter((p) => p !== '')
}

/**
 * channelFormsToWire builds the PUT body, or explains what is missing. The
 * daemon validates too; this only saves a round trip for the two refusals
 * every first attempt hits: no channel, and no `on` filter (a channel nobody
 * has told what to send is silent, PRD §11).
 */
export function channelFormsToWire(
  f: ChannelForms,
): { channels: WireNotifications } | { error: string } {
  const channels: WireNotifications = {}
  if (f.telegram.enabled) {
    channels.Telegram = { ChatID: f.telegram.chatId.trim(), TokenRef: f.telegram.tokenRef.trim() }
  }
  if (f.webhook.enabled) {
    channels.Webhook = { URL: f.webhook.url.trim(), SecretRef: f.webhook.secretRef.trim() }
  }
  if (f.slack.enabled) {
    channels.Slack = { URLRef: f.slack.urlRef.trim() }
  }
  if (f.ntfy.enabled) {
    channels.Ntfy = { URL: f.ntfy.url.trim(), TokenRef: f.ntfy.tokenRef.trim() }
  }
  if (f.smtp.enabled) {
    channels.SMTP = {
      Host: f.smtp.host.trim(),
      Port: f.smtp.port.trim(),
      From: f.smtp.from.trim(),
      To: splitPatterns(f.smtp.to),
      Username: f.smtp.username.trim(),
      PasswordRef: f.smtp.passwordRef.trim(),
    }
  }
  if (!channels.Telegram && !channels.Webhook && !channels.Slack && !channels.Ntfy && !channels.SMTP) {
    return { error: 'Enable at least one channel.' }
  }
  const on = splitPatterns(f.on)
  if (on.length === 0) {
    return { error: 'Channels need an `on` filter; patterns like deploy.* or *.failed.' }
  }
  channels.On = on
  if (f.severity !== '') channels.Severity = f.severity
  return { channels }
}

/** enabledChannelKinds lists the kinds a wire record configures: the test
 * buttons and the per-project chips both read from this. */
export function enabledChannelKinds(n: WireNotifications | null | undefined): string[] {
  if (!n) return []
  const kinds: string[] = []
  if (n.Telegram) kinds.push('telegram')
  if (n.Webhook) kinds.push('webhook')
  if (n.Slack) kinds.push('slack')
  if (n.Ntfy) kinds.push('ntfy')
  if (n.SMTP) kinds.push('smtp')
  return kinds
}

// ---- backup form ----

export interface BackupForm {
  kind: 'dir' | 's3'
  dir: string
  url: string
  endpoint: string
  region: string
  accessKey: string
  secretKeyRef: string
  pathStyle: boolean
  snapshotInterval: string
  segmentInterval: string
  retention: string
}

/** emptyBackupForm is a fresh form, defaulting to a directory destination. */
export function emptyBackupForm(): BackupForm {
  return {
    kind: 'dir',
    dir: '',
    url: '',
    endpoint: '',
    region: '',
    accessKey: '',
    secretKeyRef: '',
    pathStyle: true,
    snapshotInterval: '',
    segmentInterval: '',
    retention: '',
  }
}

/** backupFormFromRecord seeds the form from the effective settings. */
export function backupFormFromRecord(
  rec: BackupSettingsRecord | null | undefined,
): BackupForm {
  const form = emptyBackupForm()
  if (!rec) return form
  if (rec.s3) {
    form.kind = 's3'
    form.url = rec.s3.url
    form.endpoint = rec.s3.endpoint
    form.region = rec.s3.region ?? ''
    form.accessKey = rec.s3.access_key ?? ''
    form.secretKeyRef = rec.s3.secret_key_ref ?? ''
    form.pathStyle = rec.s3.path_style ?? true
  } else {
    form.kind = 'dir'
    form.dir = rec.dir ?? ''
  }
  form.snapshotInterval = rec.snapshot_interval ?? ''
  form.segmentInterval = rec.segment_interval ?? ''
  form.retention = rec.retention !== undefined && rec.retention !== 0 ? String(rec.retention) : ''
  return form
}

/**
 * backupFormToRecord builds the PUT body, or explains what is missing. Shape
 * checks only: the daemon owns validation and the probe, and its 400 message
 * is surfaced verbatim.
 */
export function backupFormToRecord(
  f: BackupForm,
): { record: BackupSettingsRecord } | { error: string } {
  const record: BackupSettingsRecord = {}
  if (f.kind === 'dir') {
    const dir = f.dir.trim()
    if (dir === '') return { error: 'A directory destination needs a path.' }
    record.dir = dir
  } else {
    const url = f.url.trim()
    const endpoint = f.endpoint.trim()
    if (!url.startsWith('s3://')) {
      return { error: 'The S3 destination is s3://bucket[/prefix].' }
    }
    if (endpoint === '') return { error: 'An S3 destination also needs an endpoint.' }
    const secretKeyRef = f.secretKeyRef.trim()
    if (secretKeyRef !== '' && !secretKeyRef.startsWith('secret:')) {
      return {
        error:
          'secret_key_ref must be a secret: reference, e.g. secret:shared/backup-s3, never the key itself.',
      }
    }
    record.s3 = { url, endpoint, path_style: f.pathStyle }
    if (f.region.trim() !== '') record.s3.region = f.region.trim()
    if (f.accessKey.trim() !== '') record.s3.access_key = f.accessKey.trim()
    if (secretKeyRef !== '') record.s3.secret_key_ref = secretKeyRef
  }
  if (f.snapshotInterval.trim() !== '') record.snapshot_interval = f.snapshotInterval.trim()
  if (f.segmentInterval.trim() !== '') record.segment_interval = f.segmentInterval.trim()
  const retention = f.retention.trim()
  if (retention !== '') {
    const n = Number(retention)
    if (!Number.isInteger(n) || n < 0) {
      return { error: 'Retention is a whole number of archives to keep.' }
    }
    if (n > 0) record.retention = n
  }
  return { record }
}

/** describeBackupSource maps the view's source onto a badge. */
export function describeBackupSource(source: string): {
  label: string
  variant: 'ok' | 'muted' | 'error'
} {
  switch (source) {
    case 'store':
      return { label: 'from settings', variant: 'ok' }
    case 'flags':
      return { label: 'from unit flags', variant: 'muted' }
    default:
      return { label: 'not configured', variant: 'error' }
  }
}
