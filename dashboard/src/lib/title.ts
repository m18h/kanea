import { matchPath } from '@/lib/paths'
import { shortID } from '@/lib/pipelines'
import { settingsTabs } from '@/lib/settings'

/**
 * What the browser tab says.
 *
 * Derived from the path rather than from each page's own heading: PageHeader's
 * title is a ReactNode and four pages pass JSX, so reading it back would mean
 * flattening nodes to text and would pick up the status pill inside the
 * service detail's h1. The path already carries what a title wants, decoded by
 * matchPath - and because the router keeps the query string separate, a title
 * keyed on the path does not churn while someone types in a filter box.
 */

/** The page name comes first: it is what stays legible in a narrowed tab. */
const brand = 'Kanea'

/** pageTitle is the one place the brand and the separator live. */
export function pageTitle(name: string): string {
  return `${name} · ${brand}`
}

/** The pages whose title is just the nav's own word for them. */
const plain: Record<string, string> = {
  '/': 'Dashboard',
  '/projects': 'Projects',
  '/services': 'Services',
  '/functions': 'Functions',
  '/pipelines': 'Pipelines',
  '/storage': 'Storage',
  '/events': 'Events',
  '/backups': 'Backups',
  '/updates': 'Updates',
}

/**
 * titleFor names the page at a path.
 *
 * Matched in App.tsx's order, because the same ambiguities apply: /services/new
 * is the deploy page and has to be tested before /services/:project/:service,
 * or it reads as a service named "new".
 */
export function titleFor(path: string): string {
  const flat = plain[normalise(path)]
  if (flat !== undefined) return pageTitle(flat)

  if (matchPath('/services/new', path)) return pageTitle('Deploy service')

  const edit = matchPath('/services/:project/:service/edit', path)
  if (edit?.project && edit.service) {
    return pageTitle(`Edit ${edit.project}/${edit.service}`)
  }

  // project/service, the form every other surface uses: a service name is
  // unique only inside its project.
  const service = matchPath('/services/:project/:service', path)
  if (service?.project && service.service) {
    return pageTitle(`${service.project}/${service.service}`)
  }

  // The run id is short but present: two open run tabs are otherwise the same
  // tab twice.
  const run = matchPath('/pipelines/:project/:service/:id', path)
  if (run?.project && run.service && run.id) {
    return pageTitle(`${run.project}/${run.service} #${shortID(run.id)}`)
  }

  const settings = matchPath('/settings/:tab', path)
  if (settings?.tab !== undefined) {
    // A tab that does not exist falls back to the bare page, because that is
    // what the page itself shows: the title may not name a tab the reader
    // cannot see.
    const tab = settingsTabs.find((t) => t.id === settings.tab)
    return pageTitle(tab ? `${tab.label} · Settings` : 'Settings')
  }
  if (matchPath('/settings', path)) return pageTitle('Settings')

  // Said out loud, like the page's own "No such page.": a tab reading the
  // app's name over an error is how a broken link looks like a slow one.
  return pageTitle('Not found')
}

function normalise(path: string): string {
  const trimmed = path.replace(/\/+$/, '')
  return trimmed === '' ? '/' : trimmed
}
