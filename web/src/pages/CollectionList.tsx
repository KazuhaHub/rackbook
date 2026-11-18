import { useMemo, type CSSProperties } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { useTable } from '@refinedev/react-table'
import {
  type ColumnDef,
  type ColumnFiltersState,
  type FilterFn,
  type SortingState,
  type Updater,
  type VisibilityState,
  type Row as TRow,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ChevronsUpDown, Columns3, Plus, Search, X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { CellValue } from '@/components/CellValue'
import { EmptyState, NotFound, PageHeader } from '@/components/common'
import { FacetFilter, type FacetOption } from '@/components/FacetFilter'
import { NotesPanel } from '@/components/NotesPanel'
import { t } from '@/i18n/zh-CN'
import { errorMessage } from '@/lib/api'
import { useFirstRender, useRefLookups } from '@/lib/hooks'
import { CollectionIcon } from '@/components/CollectionIcon'
import { canEdit, defaultColumns, fieldTitle, looksMono, recordHref, schemaProps, str } from '@/lib/ledger'
import type { Collection, Facet, LedgerRecord } from '@/lib/types'
import { cn } from '@/lib/utils'
import { useCollection, useMeta } from '@/providers/meta'

const collator = new Intl.Collator(['zh-CN', 'en'], { numeric: true, sensitivity: 'base' })

/** Values a row offers to a facet (arrays contribute each element). */
function rowValues(v: unknown): string[] {
  if (v === undefined || v === null || v === '') return []
  return (Array.isArray(v) ? v : [v]).map(str)
}

function matches(f: Facet, vals: string[], sel: string) {
  switch (f.match) {
    case 'contains':
      return vals.some((v) => v.includes(sel))
    case 'prefix':
      return vals.some((v) => v.startsWith(sel))
    default:
      return vals.includes(sel)
  }
}

const searchText = new WeakMap<object, string>()
function textOf(rec: LedgerRecord) {
  let s = searchText.get(rec)
  if (s === undefined) {
    s = Object.values(rec.data).map(str).join('\u0001').toLowerCase()
    searchText.set(rec, s)
  }
  return s
}

function useUrlTableState(col: Collection, fields: string[]) {
  const [sp, setSp] = useSearchParams()
  const defaults = useMemo(() => defaultColumns(col), [col])
  const patch = (fn: (p: URLSearchParams) => void) =>
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev)
        fn(n)
        return n
      },
      { replace: true },
    )

  const q = sp.get('q') ?? ''
  const sortParam = sp.get('sort') ?? ''
  const sorting: SortingState = sortParam ? [{ id: sortParam.replace(/^-/, ''), desc: sortParam.startsWith('-') }] : []
  const colsParam = sp.get('cols')
  const visible = new Set(colsParam ? colsParam.split(',') : defaults)
  const columnVisibility: VisibilityState = Object.fromEntries(fields.map((f) => [f, visible.has(f)]))
  const facetFields = (col.facets ?? []).map((f) => f.field)
  const columnFilters: ColumnFiltersState = facetFields
    .map((f) => ({ id: f, value: sp.getAll('f.' + f) }))
    .filter((x) => x.value.length)

  return {
    q,
    sorting,
    columnVisibility,
    columnFilters,
    hasFilters: !!q || columnFilters.length > 0,
    setQ: (v: string) => patch((p) => (v ? p.set('q', v) : p.delete('q'))),
    setSorting: (u: Updater<SortingState>) => {
      const next = typeof u === 'function' ? u(sorting) : u
      patch((p) => (next.length ? p.set('sort', (next[0].desc ? '-' : '') + next[0].id) : p.delete('sort')))
    },
    setVisibility: (u: Updater<VisibilityState>) => {
      const next = typeof u === 'function' ? u(columnVisibility) : u
      const list = fields.filter((f) => next[f] !== false)
      const same = list.length === defaults.length && list.every((f) => defaults.includes(f))
      patch((p) => (same ? p.delete('cols') : p.set('cols', list.join(','))))
    },
    resetVisibility: () => patch((p) => p.delete('cols')),
    setFilters: (u: Updater<ColumnFiltersState>) => {
      const next = typeof u === 'function' ? u(columnFilters) : u
      patch((p) => {
        for (const f of facetFields) p.delete('f.' + f)
        for (const x of next) for (const v of x.value as string[]) p.append('f.' + x.id, v)
      })
    },
    clear: () =>
      patch((p) => {
        p.delete('q')
        for (const f of facetFields) p.delete('f.' + f)
      }),
  }
}

export default function CollectionList() {
  const { collection } = useParams()
  const col = useCollection(collection)
  if (!col) return <NotFound />
  return <CollectionTable key={col.name} col={col} />
}

function CollectionTable({ col }: { col: Collection }) {
  const { meta } = useMeta()
  const navigate = useNavigate()
  const lookups = useRefLookups(col)
  const editable = canEdit(meta)

  const fields = useMemo(() => {
    const f = schemaProps(col).map(([k]) => k)
    for (const x of [...(col.list ?? []), ...(col.facets ?? []).map((x) => x.field)]) if (!f.includes(x)) f.push(x)
    return f
  }, [col])
  const url = useUrlTableState(col, fields)
  const facetByField = useMemo(() => new Map((col.facets ?? []).map((f) => [f.field, f])), [col])

  const columns = useMemo<ColumnDef<LedgerRecord>[]>(
    () =>
      fields.map((field) => {
        const facet = facetByField.get(field)
        const filterFn: FilterFn<LedgerRecord> | undefined = facet
          ? (row, id, sel: string[]) => {
              const vals = rowValues(row.getValue(id))
              return sel.some((s) => matches(facet, vals, s))
            }
          : undefined
        if (filterFn) filterFn.autoRemove = (v: string[]) => !v?.length
        return {
          id: field,
          accessorFn: (r) => r.data[field],
          header: fieldTitle(col, field),
          filterFn,
          sortUndefined: 'last',
          sortingFn: (a: TRow<LedgerRecord>, b: TRow<LedgerRecord>, id: string) => {
            const x = a.getValue(id)
            const y = b.getValue(id)
            if (typeof x === 'boolean' && typeof y === 'boolean') return Number(x) - Number(y)
            return collator.compare(str(x), str(y))
          },
        } satisfies ColumnDef<LedgerRecord>
      }),
    [fields, facetByField, col],
  )

  const { reactTable: table, refineCore } = useTable<LedgerRecord>({
    columns,
    refineCoreProps: {
      resource: col.name,
      syncWithLocation: false,
      pagination: { mode: 'off' },
      filters: { mode: 'off' },
      sorters: { mode: 'off' },
    },
    state: {
      sorting: url.sorting,
      columnFilters: url.columnFilters,
      globalFilter: url.q,
      columnVisibility: url.columnVisibility,
    },
    onSortingChange: url.setSorting,
    onColumnFiltersChange: url.setFilters,
    onColumnVisibilityChange: url.setVisibility,
    onGlobalFilterChange: () => {},
    manualFiltering: false,
    manualSorting: false,
    enableSortingRemoval: true,
    getColumnCanGlobalFilter: () => true,
    globalFilterFn: (row, _id, value: string) => {
      const text = textOf(row.original)
      return String(value)
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean)
        .every((tok) => text.includes(tok))
    },
  })

  const queryData = refineCore.tableQuery.data?.data
  const all = useMemo(() => (queryData ?? []) as LedgerRecord[], [queryData])
  const rows = table.getRowModel().rows
  const freshRows = useFirstRender(all.length > 0)
  const visibleCols = table.getVisibleLeafColumns()

  const facetOptions = useMemo(() => {
    const out = new Map<string, FacetOption[]>()
    for (const f of col.facets ?? []) {
      const counts = new Map<string, number>()
      if (f.values?.length) {
        for (const v of f.values) counts.set(v, all.filter((r) => matches(f, rowValues(r.data[f.field]), v)).length)
      } else {
        for (const r of all) for (const v of new Set(rowValues(r.data[f.field]))) counts.set(v, (counts.get(v) ?? 0) + 1)
      }
      const prop = col.schema.properties?.[f.field]
      const label = (v: string) => (prop?.type === 'boolean' ? (v === 'true' ? t.common.yes : t.common.no) : v)
      const opts = [...counts].map(([value, count]) => ({ value, label: label(value), count }))
      if (!f.values?.length) opts.sort((a, b) => collator.compare(a.label, b.label))
      out.set(f.field, opts)
    }
    return out
  }, [col, all])

  const colTitle = (id: string) => fieldTitle(col, id)

  return (
    <div>
      <PageHeader
        icon={<CollectionIcon col={col} className="size-5" />}
        title={col.title}
        description={col.description}
        actions={
          editable && (
            <Button render={<Link to={`/c/${encodeURIComponent(col.name)}/-/new`} />}>
              <Plus /> {t.list.create}
            </Button>
          )
        }
      />
      <NotesPanel notes={col.notes ?? []} />

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={url.q}
            onChange={(e) => url.setQ(e.target.value)}
            placeholder={t.list.filterPlaceholder}
            className="h-8 pl-8"
          />
        </div>
        {(col.facets ?? []).map((f) => (
          <FacetFilter
            key={f.field}
            label={colTitle(f.field)}
            options={facetOptions.get(f.field) ?? []}
            selected={(table.getColumn(f.field)?.getFilterValue() as string[] | undefined) ?? []}
            onChange={(v) => table.getColumn(f.field)?.setFilterValue(v.length ? v : undefined)}
          />
        ))}
        <div className="ml-auto flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
              <Columns3 /> {t.list.columns}
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="min-w-48">
              <DropdownMenuGroup>
                <DropdownMenuLabel>{t.list.toggleColumns}</DropdownMenuLabel>
              </DropdownMenuGroup>
              <DropdownMenuSeparator />
              {table.getAllLeafColumns().map((c) => (
                <DropdownMenuCheckboxItem
                  key={c.id}
                  checked={c.getIsVisible()}
                  onCheckedChange={(v) => c.toggleVisibility(!!v)}
                >
                  {colTitle(c.id)}
                </DropdownMenuCheckboxItem>
              ))}
              <DropdownMenuSeparator />
              <DropdownMenuItem onClick={url.resetVisibility}>{t.list.resetColumns}</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {url.columnFilters.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          {url.columnFilters.flatMap((cf) =>
            (cf.value as string[]).map((v) => {
              const opt = facetOptions.get(cf.id)?.find((o) => o.value === v)
              return (
                <Badge key={cf.id + v} variant="secondary" className="h-6 gap-1 pr-1">
                  <span className="text-muted-foreground">{colTitle(cf.id)}:</span> {opt?.label ?? v}
                  <button
                    type="button"
                    aria-label={t.list.removeFilter}
                    className="rounded-full p-0.5 hover:bg-foreground/10"
                    onClick={() =>
                      table.getColumn(cf.id)?.setFilterValue((cf.value as string[]).filter((x) => x !== v))
                    }
                  >
                    <X className="size-3" />
                  </button>
                </Badge>
              )
            }),
          )}
          <Button variant="ghost" size="xs" onClick={url.clear}>
            {t.list.clearFilters}
          </Button>
        </div>
      )}

      {refineCore.tableQuery.isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="h-9 w-full" />
          ))}
        </div>
      ) : refineCore.tableQuery.isError ? (
        <EmptyState title={t.errors.generic} body={errorMessage(refineCore.tableQuery.error)} />
      ) : all.length === 0 ? (
        <EmptyState icon={<CollectionIcon col={col} className="size-8" />} title={t.list.emptyCollection} />
      ) : (
        <>
          <div className="max-h-[70vh] overflow-auto rounded-xl border bg-card shadow-xs">
            <table className="w-max min-w-full border-collapse text-sm">
              <thead className="sticky top-0 z-10 bg-muted/95 shadow-[0_1px_0_var(--border)] backdrop-blur">
                <tr className="border-b">
                  {visibleCols.map((c) => {
                    const dir = c.getIsSorted()
                    return (
                      <th
                        key={c.id}
                        scope="col"
                        aria-sort={dir ? (dir === 'asc' ? 'ascending' : 'descending') : 'none'}
                        className="h-10 px-4 text-left align-middle text-xs font-semibold tracking-wide whitespace-nowrap text-muted-foreground"
                      >
                        <button
                          type="button"
                          onClick={c.getToggleSortingHandler()}
                          className="-mx-1.5 inline-flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-foreground/5 hover:text-foreground"
                          title={dir === 'asc' ? t.list.sortAsc : dir === 'desc' ? t.list.sortDesc : undefined}
                        >
                          {colTitle(c.id)}
                          {dir === 'asc' ? (
                            <ArrowUp className="size-3" />
                          ) : dir === 'desc' ? (
                            <ArrowDown className="size-3" />
                          ) : (
                            <ChevronsUpDown className="size-3 opacity-40" />
                          )}
                        </button>
                      </th>
                    )
                  })}
                </tr>
              </thead>
              <tbody>
                {rows.map((row, ri) => {
                  const rec = row.original
                  const href = recordHref(col.name, rec.id)
                  // only the first screenful animates; long tables appear at once
                  const animate = freshRows && ri < 20
                  return (
                    <tr
                      key={rec.id}
                      style={animate ? ({ '--i': ri } as CSSProperties) : undefined}
                      className={cn(
                        'cursor-pointer border-b transition-colors duration-150 last:border-0 even:bg-muted/25 hover:bg-brand/[0.07]',
                        animate && 'rb-row-in',
                      )}
                      onClick={(e) => {
                        if ((e.target as HTMLElement).closest('a,button')) return
                        navigate(href)
                      }}
                    >
                      {visibleCols.map((c, i) => {
                        const v = rec.data[c.id]
                        return (
                          <td key={c.id} className={cn('px-4 py-2.5 align-top', i === 0 && 'font-medium')}>
                            {i === 0 && !lookups[c.id] ? (
                              <Link to={href} className={cn('hover:underline', looksMono(str(v)) && 'font-mono text-[0.8125rem]')}>
                                {str(v) || t.show.empty}
                              </Link>
                            ) : (
                              <CellValue value={v} lookup={lookups[c.id]} />
                            )}
                          </td>
                        )
                      })}
                    </tr>
                  )
                })}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={Math.max(visibleCols.length, 1)} className="py-12 text-center text-muted-foreground">
                      {t.list.empty}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="mt-2 text-xs text-muted-foreground tabular-nums">{t.list.rows(rows.length, all.length)}</div>
        </>
      )}
    </div>
  )
}
