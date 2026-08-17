import { z } from 'zod'
import { apiFetch, csrfHeader, requestTimeout } from './session'

/**
 * The spec editor's wire surface (PRD §12.2, v1.38).
 *
 * Render is validate: HCL in, diagnostics with file/line out; no side
 * effects. Apply renders the same bytes server-side and applies through the
 * same path `PUT /v1/services` uses, so a validated preview cannot drift from
 * what is applied. Source is generated HCL for the current desired state.
 */

export const diagnosticSchema = z.object({
  severity: z.enum(['error', 'warning']).catch('error'),
  summary: z.string(),
  detail: z.string().optional(),
  file: z.string().optional(),
  line: z.number().optional(),
  column: z.number().optional(),
})

// The rendered services come back as the same Desired JSON /v1/services
// serves. The editor only summarises them, so this schema names the fields
// the preview reads and passes the rest through.
export const renderedServiceSchema = z
  .object({
    Project: z.string(),
    Service: z.string(),
    Count: z.number(),
    Image: z.string(),
  })
  .passthrough()

export const renderResponseSchema = z.object({
  valid: z.boolean(),
  diagnostics: z.array(diagnosticSchema).default([]),
  services: z.array(renderedServiceSchema).nullish(),
})

export const applyResponseSchema = z.object({
  applied: z.array(z.string()).default([]),
  index: z.number().optional(),
})

export const specSourceSchema = z.object({
  hcl: z.string(),
  generated: z.boolean(),
})

export type SpecDiagnostic = z.infer<typeof diagnosticSchema>
export type RenderedService = z.infer<typeof renderedServiceSchema>
export type RenderResponse = z.infer<typeof renderResponseSchema>
export type ApplyResponse = z.infer<typeof applyResponseSchema>

/** Validate a spec server-side. */
export async function renderSpec(
  hcl: string,
  project: string | undefined,
  csrf?: string,
): Promise<RenderResponse> {
  const resp = await apiFetch('/v1/spec/render', {
    method: 'POST',
    body: { files: { 'editor.hcl': hcl }, ...(project ? { project } : {}) },
    ...(csrf ? { csrf } : {}),
  })
  return renderResponseSchema.parse(await resp.json())
}

/**
 * Apply a spec. A 422 carries the diagnostics as its body, so a validation
 * failure surfaces as a positioned list rather than a thrown string: the
 * result type covers both outcomes.
 */
export async function applySpec(
  hcl: string,
  project: string | undefined,
  csrf?: string,
): Promise<{ applied: string[] } | { diagnostics: SpecDiagnostic[] }> {
  const resp = await fetch('/v1/spec/apply', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/json',
      ...(csrf ? { [csrfHeader]: csrf } : {}),
    },
    body: JSON.stringify({ files: { 'editor.hcl': hcl }, ...(project ? { project } : {}) }),
    signal: AbortSignal.timeout(requestTimeout),
  })
  if (resp.status === 422) {
    const body = renderResponseSchema.parse(await resp.json())
    return { diagnostics: body.diagnostics }
  }
  if (!resp.ok) {
    let message = `apply: ${resp.status}`
    try {
      const body: unknown = await resp.json()
      if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
        message = body.error
      }
    } catch {
      // The status is all there is.
    }
    throw new Error(message)
  }
  const body = applyResponseSchema.parse(await resp.json())
  return { applied: body.applied }
}

/** Fetch generated HCL for a service. Null when the daemon refuses (a field
 * the generator cannot express): the editor then starts from the template. */
export async function fetchSpecSource(
  project: string,
  service: string,
  signal?: AbortSignal,
): Promise<{ hcl: string } | { refusal: string }> {
  const init: RequestInit = signal ? { signal } : { signal: AbortSignal.timeout(requestTimeout) }
  const resp = await fetch(
    `/v1/spec/source?project=${encodeURIComponent(project)}&service=${encodeURIComponent(service)}`,
    init,
  )
  if (resp.status === 422) {
    try {
      const body: unknown = await resp.json()
      if (body && typeof body === 'object' && 'error' in body && typeof body.error === 'string') {
        return { refusal: body.error }
      }
    } catch {
      // fall through
    }
    return { refusal: 'this service uses spec features the generator cannot express' }
  }
  if (!resp.ok) throw new Error(`spec source: ${resp.status}`)
  return { hcl: specSourceSchema.parse(await resp.json()).hcl }
}

/** The blank-deploy starting point, following PRD §6.1's minimal shape. */
export const HCL_TEMPLATE = `spec_version = 1

project "myproject" {}

service "web" {
  project = "myproject"
  count   = 1

  task "app" {
    image = "nginx:1.29-alpine"

    resources {
      cpu    = 250  # MHz
      memory = 128  # MiB
    }
  }

  network {
    port "http" { container = 80 }
  }

  # Uncomment to route a domain through the edge:
  # expose {
  #   domains = ["web.example.com"]
  # }
}
`
