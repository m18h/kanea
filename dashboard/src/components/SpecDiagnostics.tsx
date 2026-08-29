import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import type { SpecDiagnostic } from '@/lib/spec'

/**
 * DiagnosticList positions the daemon's findings for an editor. Shared by the
 * full-page spec editor and the service detail page's inline one (v1.103).
 */
export function DiagnosticList({
  diagnostics,
  onJump,
}: {
  diagnostics: SpecDiagnostic[]
  onJump: (line: number) => void
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Diagnostics</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {diagnostics.map((d, i) => (
          <div key={i} className="flex items-start gap-2.5 text-sm">
            <Badge
              variant={d.severity === 'error' ? 'error' : 'warn'}
              className="font-mono text-[11px]"
            >
              {d.severity}
            </Badge>
            <div className="min-w-0">
              {/* Daemon-composed text quoting operator input: text, never markup. */}
              <span>{d.summary}</span>
              {d.line !== undefined && d.line > 0 ? (
                <button
                  type="button"
                  className="ml-2 font-mono text-xs text-primary hover:underline"
                  onClick={() => onJump(d.line ?? 1)}
                >
                  line {d.line}
                  {d.column !== undefined && d.column > 0 ? `:${d.column}` : ''}
                </button>
              ) : null}
              {d.detail ? (
                <p className="mt-0.5 text-xs text-muted-foreground">{d.detail}</p>
              ) : null}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

/**
 * jumpToLine moves a textarea's caret to a diagnostic's line. It touches the
 * DOM element, so it lives beside the component rather than in lib/.
 */
export function jumpToLine(el: HTMLTextAreaElement | null, text: string, line: number) {
  if (!el) return
  let offset = 0
  const lines = text.split('\n')
  for (let i = 0; i < Math.min(line - 1, lines.length); i++) {
    offset += (lines[i]?.length ?? 0) + 1
  }
  el.focus()
  el.setSelectionRange(offset, offset)
}
