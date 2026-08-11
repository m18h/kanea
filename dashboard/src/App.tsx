import { Router } from '@/lib/router'
import { useRouter } from '@/hooks/useRouter'
import { matchPath } from '@/lib/paths'
import { AppShell } from '@/components/layout/AppShell'
import { Overview } from '@/pages/Overview'
import { Services } from '@/pages/Services'
import { ServiceDetail } from '@/pages/ServiceDetail'
import { Functions } from '@/pages/Functions'
import { Pipelines } from '@/pages/Pipelines'
import { PipelineDetail } from '@/pages/PipelineDetail'
import { Events } from '@/pages/Events'
import { Backups } from '@/pages/Backups'
import { Settings } from '@/pages/Settings'
import { Login } from '@/pages/Login'
import { SpecEditorPage } from '@/pages/SpecEditorPage'
import { SessionProvider } from '@/lib/session-provider'
import { useSession } from '@/hooks/useSession'

export function App() {
  return (
    <SessionProvider>
      <Router>
        <Gate />
      </Router>
    </SessionProvider>
  )
}

/**
 * Gate decides between the app and the login screen.
 *
 * The daemon is the authority — every route behind this is deny-by-default —
 * so this is presentation, not enforcement. Skipping it would not expose data;
 * it would show an operator a screen full of 401s instead of a password field.
 */
function Gate() {
  const { session, loading } = useSession()

  if (loading) {
    // Deliberately blank rather than a spinner: the answer usually arrives in
    // a few milliseconds, and a flashed skeleton is worse than a still page.
    return <div className="min-h-screen bg-background" />
  }
  if (!session) return <Login />
  return <Shell />
}

function Shell() {
  const { path } = useRouter()
  return (
    <AppShell>
      <Page path={path} />
    </AppShell>
  )
}

/** Page resolves the current path to a view. */
function Page({ path }: { path: string }) {
  if (matchPath('/', path)) return <Overview />
  if (matchPath('/services', path)) return <Services />
  if (matchPath('/services/new', path)) return <SpecEditorPage />

  const edit = matchPath('/services/:project/:service/edit', path)
  if (edit?.project && edit.service) {
    return <SpecEditorPage project={edit.project} service={edit.service} />
  }

  const detail = matchPath('/services/:project/:service', path)
  if (detail?.project && detail.service) {
    return <ServiceDetail project={detail.project} service={detail.service} />
  }

  if (matchPath('/functions', path)) return <Functions />
  if (matchPath('/pipelines', path)) return <Pipelines />

  const run = matchPath('/pipelines/:project/:service/:id', path)
  if (run?.project && run.service && run.id) {
    return <PipelineDetail project={run.project} service={run.service} id={run.id} />
  }

  if (matchPath('/events', path)) return <Events />
  if (matchPath('/backups', path)) return <Backups />
  if (matchPath('/settings', path)) return <Settings />

  // A deep link the server handed to the app but the app does not know: say so
  // rather than render a blank page.
  return <p className="text-sm text-muted-foreground">No such page.</p>
}
