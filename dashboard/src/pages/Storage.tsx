import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { Link } from '@/lib/router'
import { Badge } from '@/components/ui/badge'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table'
import { TableSkeleton } from '@/components/Skeletons'
import { PageHeader } from '@/components/PageHeader'
import { FilterChips } from '@/components/FilterChips'
import { SortHeader } from '@/components/SortHeader'
import { StatTile } from '@/components/StatTile'
import { StatusDot, type StatusTone } from '@/components/StatusDot'
import { PaginationControls } from '@/components/Pagination'
import { usePagination } from '@/hooks/usePagination'
import { sortItems, useSort } from '@/hooks/useSort'
import { fetchVolumes, type VolumeMount, type VolumeStorage } from '@/lib/api'
import { matchesQuery } from '@/lib/search'
import { formatBytes } from '@/lib/state'

/**
 * Storage (PRD §8, §12.2, v1.69).
 *
 * Storage resources with everything mounting them, which is what
 * `GET /v1/volumes` derives. Two facts about that derivation shape the whole
 * page and are stated on it rather than left to be discovered:
 *
 *   - A resource **nothing references does not appear**. `toDesired` inlines a
 *     storage block into every volume that uses it and nothing on the node
 *     remembers the rest, so this is a view of what is mounted, not a registry.
 *   - A `size` is a **budget, not a quota**. Nothing enforces it; a mount over
 *     its budget is still serving, which is exactly why it needs saying.
 *
 * Usage is measured on a slow background walk, so "unmeasured" is a normal
 * steady state, for an s3 volume it is permanent, because walking one is a
 * LIST per directory. It renders as a dash, never as zero: an empty volume and
 * an unwalked one are opposite facts (§9.2).
 */
export function Storage() {
  const volumes = useQuery({
    queryKey: ['volumes'],
    queryFn: ({ signal }) => fetchVolumes(signal),
    refetchInterval: 30_000,
  })

  const [query, setQuery] = useState('')
  const [type, setType] = useState('all')
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const sort = useSort<SortKey>()

  const list = (volumes.data ?? []).map(summarise)

  // The chips offer the drivers this node actually uses. A fixed list would
  // offer four filters that can only ever produce an empty table.
  const typeFilters = [
    { value: 'all', label: 'all' },
    ...[...new Set(list.map((s) => s.storage.type))].sort().map((t) => ({ value: t, label: t })),
  ]

  const filtered = list.filter(
    (s) =>
      (type === 'all' || s.storage.type === type) &&
      matchesQuery(
        query,
        `${s.storage.project}/${s.storage.name}`,
        s.storage.target,
        ...s.mounts.map((m) => `${m.project}/${m.service}`),
      ),
  )
  const sorted = sortItems(filtered, sort, {
    storage: (s) => `${s.storage.project}/${s.storage.name}`,
    type: (s) => s.storage.type,
    mounts: (s) => s.mounts.length,
    // An unmeasured resource sorts as nothing rather than as empty, both ways:
    // it holds an unknown amount, not zero.
    used: (s) => s.usedBytes,
  })
  const pager = usePagination(sorted, {
    resetKey: `${query} ${type} ${sort.key ?? ''} ${sort.dir}`,
  })

  // The tiles describe everything declared, not the filtered view.
  const mounts = list.flatMap((s) => s.mounts)
  const measured = mounts.filter((m) => m.used_bytes !== undefined)
  const measuredBytes = measured.reduce((sum, m) => sum + (m.used_bytes ?? 0), 0)
  const over = mounts.filter((m) => m.state === 'over')

  return (
    <div className="space-y-4">
      <PageHeader
        title="Storage"
        subtitle="Storage resources, their mounts, and usage where it has been measured"
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <StatTile
          label="Storage resources"
          value={list.length}
          sub={`${mounts.length} mount${mounts.length === 1 ? '' : 's'}`}
        />
        <StatTile
          label="Measured usage"
          value={measured.length > 0 ? formatBytes(measuredBytes) : '-'}
          sub={
            measured.length > 0
              ? `across ${measured.length} of ${mounts.length} mount${mounts.length === 1 ? '' : 's'}`
              : 'nothing walked yet'
          }
        />
        <StatTile
          label="Over budget"
          value={over.length}
          tone={over.length > 0 ? 'error' : 'default'}
          sub={over.length > 0 ? 'still serving; a budget is not a quota' : 'within declared sizes'}
        />
      </div>

      {volumes.error ? (
        <Card className="p-4 text-sm text-destructive">{String(volumes.error)}</Card>
      ) : volumes.isPending ? (
        <TableSkeleton rows={5} cols={6} />
      ) : list.length === 0 ? (
        <Card className="p-4 text-sm text-muted-foreground">
          No volumes are mounted. A <code className="font-mono">volume</code> block in a job
          spec declares one; a <code className="font-mono">storage</code> block nothing mounts
          does not appear here.
        </Card>
      ) : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <FilterChips options={typeFilters} value={type} onChange={setType} />
            <Input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search storage, target or service…"
              aria-label="Search storage"
              className="h-8 w-64 text-xs"
            />
          </div>

          {sorted.length === 0 ? (
            <Card className="p-4 text-sm text-muted-foreground">
              No storage matches that filter.
            </Card>
          ) : (
            <Card className="py-2">
              <Table>
                <THead>
                  <tr>
                    <SortHeader sort={sort} sortKey="storage" className="pt-2">
                      Storage
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="type" className="pt-2">
                      Driver
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="mounts" className="pt-2">
                      Mounts
                    </SortHeader>
                    <SortHeader sort={sort} sortKey="used" className="pt-2">
                      Used
                    </SortHeader>
                    <TH className="pt-2">Budget</TH>
                    <TH className="pt-2">State</TH>
                  </tr>
                </THead>
                <TBody>
                  {pager.pageItems.map((row) => (
                    <StorageRows
                      key={`${row.storage.project}/${row.storage.name}`}
                      row={row}
                      open={open[key(row)] ?? false}
                      onToggle={() => setOpen((o) => ({ ...o, [key(row)]: !o[key(row)] }))}
                    />
                  ))}
                </TBody>
              </Table>
              <div className="px-3">
                <PaginationControls state={pager} />
              </div>
            </Card>
          )}
        </>
      )}

      <p className="text-xs text-muted-foreground">
        A <code className="font-mono">size</code> is a budget the sampler measures against, not a
        quota the node enforces: nothing stops a volume growing past it, and the number is the
        reason to go and look. An <code className="font-mono">s3</code> volume is never walked,
        so it stays unmeasured by design. A <code className="font-mono">local</code> volume
        exists once per alloc, each with its own contents, and is listed once per alloc for the
        same reason.
      </p>
    </div>
  )
}

type SortKey = 'storage' | 'type' | 'mounts' | 'used'

/** A storage resource with the totals the table shows. */
interface StorageRow {
  storage: VolumeStorage
  mounts: VolumeMount[]
  /** usedBytes is absent when nothing under this resource has been measured. */
  usedBytes: number | undefined
  /** sizeBytes is absent when no mount declared a budget. */
  sizeBytes: number | undefined
  state: 'over' | 'ok' | 'partial' | 'unmeasured'
}

function key(row: StorageRow): string {
  return `${row.storage.project}/${row.storage.name}`
}

/**
 * summarise rolls a resource's mounts up into one row.
 *
 * A total is the sum of what was *measured*, and it is absent rather than zero
 * when nothing was: summing an unmeasured mount as zero would hide one alloc
 * filling a disk behind two siblings that were never walked.
 */
function summarise(storage: VolumeStorage): StorageRow {
  const mounts = storage.mounts ?? []
  const measured = mounts.filter((m) => m.used_bytes !== undefined)
  const budgeted = mounts.filter((m) => m.size_bytes !== undefined)

  const state: StorageRow['state'] = mounts.some((m) => m.state === 'over')
    ? 'over'
    : measured.length === 0
      ? 'unmeasured'
      : measured.length < mounts.length
        ? 'partial'
        : 'ok'

  return {
    storage,
    mounts,
    usedBytes:
      measured.length > 0 ? measured.reduce((sum, m) => sum + (m.used_bytes ?? 0), 0) : undefined,
    sizeBytes:
      budgeted.length > 0 ? budgeted.reduce((sum, m) => sum + (m.size_bytes ?? 0), 0) : undefined,
    state,
  }
}

const stateTone: Record<StorageRow['state'], StatusTone> = {
  over: 'error',
  ok: 'ok',
  partial: 'info',
  unmeasured: 'muted',
}

const stateWord: Record<StorageRow['state'], string> = {
  over: 'over budget',
  ok: 'ok',
  partial: 'partly measured',
  unmeasured: 'unmeasured',
}

/** StorageRows is the resource row plus, when expanded, one row per mount. */
function StorageRows({
  row,
  open,
  onToggle,
}: {
  row: StorageRow
  open: boolean
  onToggle: () => void
}) {
  const label = `${row.storage.project}/${row.storage.name}`

  return (
    <>
      <TR>
        <TD>
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={open}
            className="group flex items-center gap-1.5 text-left"
          >
            {open ? (
              <ChevronDown size={14} className="shrink-0 text-muted-foreground" aria-hidden />
            ) : (
              <ChevronRight size={14} className="shrink-0 text-muted-foreground" aria-hidden />
            )}
            <span>
              <span className="font-medium group-hover:underline">{label}</span>
              {/* Targets come from a job spec and render as text (§14 A03). */}
              {row.storage.target ? (
                <span className="block font-mono text-xs text-muted-foreground">
                  {row.storage.target}
                </span>
              ) : null}
            </span>
          </button>
        </TD>
        <TD>
          <Badge variant="muted" className="font-mono text-[11px]">
            {row.storage.type}
          </Badge>
        </TD>
        <TD className="font-mono tabular-nums">{row.mounts.length}</TD>
        <TD className="font-mono tabular-nums">
          {row.usedBytes === undefined ? '-' : formatBytes(row.usedBytes)}
        </TD>
        <TD className="font-mono tabular-nums text-muted-foreground">
          {row.sizeBytes === undefined ? '-' : formatBytes(row.sizeBytes)}
        </TD>
        <TD>
          <StatusDot tone={stateTone[row.state]} label={stateWord[row.state]} />
        </TD>
      </TR>

      {open
        ? row.mounts.map((mount) => (
            <MountRow key={`${mount.project}/${mount.service}/${mount.volume}`} mount={mount} />
          ))
        : null}
    </>
  )
}

function MountRow({ mount }: { mount: VolumeMount }) {
  const tone: StatusTone =
    mount.state === 'over' ? 'error' : mount.state === 'ok' ? 'ok' : 'muted'

  return (
    <TR className="bg-muted/20">
      <TD className="pl-9">
        <Link
          to={`/services/${mount.project}/${mount.service}`}
          className="font-medium hover:underline"
        >
          {mount.project}/{mount.service}
        </Link>
        <span className="block font-mono text-xs text-muted-foreground">
          {mount.volume}
          {mount.mount_path ? ` → ${mount.mount_path}` : ''}
          {mount.read_only ? ' (ro)' : ''}
        </span>
      </TD>
      <TD className="font-mono text-xs text-muted-foreground" colSpan={2}>
        {mount.path ?? '-'}
      </TD>
      <TD className="font-mono tabular-nums">
        {mount.used_bytes === undefined ? '-' : formatBytes(mount.used_bytes)}
      </TD>
      <TD className="font-mono tabular-nums text-muted-foreground">
        {mount.size_bytes === undefined ? '-' : formatBytes(mount.size_bytes)}
      </TD>
      <TD>
        <StatusDot tone={tone} label={mount.state} />
      </TD>
    </TR>
  )
}
