import { describe, expect, it } from 'vitest'
import {
  backupFormFromRecord,
  backupFormToRecord,
  channelFormsFromWire,
  channelFormsToWire,
  describeBackupSource,
  emptyBackupForm,
  emptyChannelForms,
  enabledChannelKinds,
  isZeroTime,
  splitPatterns,
  timeOrNever,
} from './settings'

describe('isZeroTime', () => {
  it('treats absence and the Go zero time as never', () => {
    expect(isZeroTime(undefined)).toBe(true)
    expect(isZeroTime('')).toBe(true)
    // A token's expires field cannot omit itself: a struct field ignores
    // omitempty, so "never" arrives as year one.
    expect(isZeroTime('0001-01-01T00:00:00Z')).toBe(true)
    expect(isZeroTime('2026-01-01T00:00:00Z')).toBe(false)
  })

  it('renders never rather than year one', () => {
    expect(timeOrNever('0001-01-01T00:00:00Z')).toBe('never')
    expect(timeOrNever(undefined)).toBe('never')
    expect(timeOrNever('2026-01-01T00:00:00Z')).not.toBe('never')
    expect(timeOrNever('not a date')).toBe('not a date')
  })
})

describe('splitPatterns', () => {
  it('accepts commas, spaces and both', () => {
    expect(splitPatterns('deploy.*, *.failed backup.*')).toEqual([
      'deploy.*',
      '*.failed',
      'backup.*',
    ])
    expect(splitPatterns('  ')).toEqual([])
    expect(splitPatterns('')).toEqual([])
  })
})

describe('channel forms', () => {
  it('round-trips a wire record through the form and back', () => {
    const forms = channelFormsFromWire({
      Webhook: { URL: 'https://example.com/hook', SecretRef: 'secret:shared/hook' },
      SMTP: {
        Host: 'mail.example.com',
        Port: '587',
        From: 'kanea@example.com',
        To: ['ops@example.com', 'dev@example.com'],
        Username: 'kanea',
        PasswordRef: 'secret:shared/smtp',
      },
      On: ['deploy.*', '*.failed'],
      Severity: 'warning',
    })
    expect(forms.webhook.enabled).toBe(true)
    expect(forms.telegram.enabled).toBe(false)
    expect(forms.smtp.to).toBe('ops@example.com, dev@example.com')
    expect(forms.on).toBe('deploy.*, *.failed')

    const built = channelFormsToWire(forms)
    if ('error' in built) throw new Error(built.error)
    expect(built.channels.Webhook).toEqual({
      URL: 'https://example.com/hook',
      SecretRef: 'secret:shared/hook',
    })
    expect(built.channels.SMTP?.To).toEqual(['ops@example.com', 'dev@example.com'])
    expect(built.channels.On).toEqual(['deploy.*', '*.failed'])
    expect(built.channels.Severity).toBe('warning')
    // Disabled channels never appear in the body at all — a null would read
    // as an explicit clear, and an absent key is the honest shape.
    expect('Telegram' in built.channels).toBe(false)
  })

  it('seeds an empty form from nothing', () => {
    expect(channelFormsFromWire(null)).toEqual(emptyChannelForms())
    expect(channelFormsFromWire(undefined)).toEqual(emptyChannelForms())
  })

  it('refuses a record with no channel enabled', () => {
    const built = channelFormsToWire(emptyChannelForms())
    expect('error' in built && built.error).toMatch(/at least one channel/)
  })

  it('refuses a channel with no on filter — silent channels are the v1.24 bug', () => {
    const forms = emptyChannelForms()
    forms.slack = { enabled: true, urlRef: 'secret:shared/slack' }
    const built = channelFormsToWire(forms)
    expect('error' in built && built.error).toMatch(/on.*filter/)
  })

  it('omits the default severity rather than sending an empty string', () => {
    const forms = emptyChannelForms()
    forms.slack = { enabled: true, urlRef: 'secret:shared/slack' }
    forms.on = 'deploy.*'
    const built = channelFormsToWire(forms)
    if ('error' in built) throw new Error(built.error)
    expect('Severity' in built.channels).toBe(false)
  })

  it('lists the enabled kinds for the test buttons and project chips', () => {
    expect(enabledChannelKinds(null)).toEqual([])
    expect(
      enabledChannelKinds({ Slack: { URLRef: 'secret:x' }, Ntfy: { URL: 'https://ntfy.sh/k' } }),
    ).toEqual(['slack', 'ntfy'])
  })
})

describe('backup form', () => {
  it('round-trips an S3 record', () => {
    const form = backupFormFromRecord({
      s3: {
        url: 's3://kanea/backups',
        endpoint: 'https://s3.example.com',
        region: 'us-east-1',
        access_key: 'AK',
        secret_key_ref: 'secret:shared/backup-s3',
        path_style: false,
      },
      snapshot_interval: '6h0m0s',
      retention: 10,
    })
    expect(form.kind).toBe('s3')
    expect(form.pathStyle).toBe(false)
    expect(form.retention).toBe('10')

    const built = backupFormToRecord(form)
    if ('error' in built) throw new Error(built.error)
    expect(built.record.s3?.url).toBe('s3://kanea/backups')
    expect(built.record.s3?.secret_key_ref).toBe('secret:shared/backup-s3')
    expect(built.record.snapshot_interval).toBe('6h0m0s')
    expect(built.record.retention).toBe(10)
    expect(built.record.dir).toBeUndefined()
  })

  it('round-trips a directory record and defaults path style on', () => {
    const form = backupFormFromRecord({ dir: '/var/backups/kanea' })
    expect(form.kind).toBe('dir')
    expect(form.pathStyle).toBe(true)

    const built = backupFormToRecord(form)
    if ('error' in built) throw new Error(built.error)
    expect(built.record).toEqual({ dir: '/var/backups/kanea' })
  })

  it('seeds a fresh form from nothing', () => {
    expect(backupFormFromRecord(null)).toEqual(emptyBackupForm())
  })

  it('refuses shapes the daemon would refuse, before the round trip', () => {
    const dir = emptyBackupForm()
    expect('error' in backupFormToRecord(dir)).toBe(true)

    const s3 = { ...emptyBackupForm(), kind: 's3' as const, url: 'https://not-s3' }
    expect('error' in backupFormToRecord(s3)).toBe(true)

    const noEndpoint = { ...emptyBackupForm(), kind: 's3' as const, url: 's3://bucket' }
    expect('error' in backupFormToRecord(noEndpoint)).toBe(true)

    // A pasted key is refused by shape: the record replicates in cleartext
    // metadata terms, so only a secret: reference may travel here.
    const pastedKey = {
      ...emptyBackupForm(),
      kind: 's3' as const,
      url: 's3://bucket',
      endpoint: 'https://s3.example.com',
      secretKeyRef: 'AKIAIOSFODNN7EXAMPLE',
    }
    const refused = backupFormToRecord(pastedKey)
    expect('error' in refused && refused.error).toMatch(/never the key itself/)

    const badRetention = { ...emptyBackupForm(), dir: '/x', retention: 'ten' }
    expect('error' in backupFormToRecord(badRetention)).toBe(true)
  })

  it('maps the source onto a badge', () => {
    expect(describeBackupSource('store').label).toBe('from settings')
    expect(describeBackupSource('flags').label).toBe('from unit flags')
    expect(describeBackupSource('none').variant).toBe('error')
  })
})
