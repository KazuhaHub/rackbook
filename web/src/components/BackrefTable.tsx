import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { ChevronLeft, ChevronRight, Plus, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/ui/native-select'
import { t } from '@/i18n'
import { useInlineEdit } from '@/hooks/use-inline-edit'
import { usePageSize } from '@/hooks/use-page-size'
import { rowClass, useRowNav } from '@/hooks/use-row-nav'
import { defaultColumns, fieldTitle, looksMono, recordHref, str } from '@/lib/ledger'
import { filterRows, PAGE_SIZES, paginate } from '@/lib/tableView'
import type { Backref, Collection, LedgerRecord } from '@/lib/types'
import { useRefLookups } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { RecordCell } from './RecordCell'

/** The backref columns of a collection: the ref rule's backref_columns, else the list columns, without the referencing field. */
export function backrefColumns(col: Collection, backrefs: Backref[]): string[] {
  const hidden = new Set(backrefs.map((b) => b.field))
  const configured = backrefs.find((b) => b.columns?.length)?.columns?.filter((c) => !!col.schema.properties?.[c] && !hidden.has(c))
  return configured?.length ? configured : defaultColumns(col).filter((c) => !hidden.has(c))
}

/**
 * The records of one collection that reference the record on screen, as a table
 * with quick search, rows per page and paging. `records` are already the own or the
 * general ones; `generic` only changes the wording and hides "add".
 */
export function BackrefTable({
  col,
  backrefs,
  records,
  parent,
  editable,
  generic,
  onChanged,
}: {
  col: Collection
  backrefs: Backref[]
  records: LedgerRecord[]
  parent: LedgerRecord
  editable: boolean
  generic: boolean
  onChanged: () => void
}) {
  const lookups = useRefLookups(col)
  const edit = useInlineEdit(col, onChanged)
  const rowNav = useRowNav()
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [size, setSize] = usePageSize(col.name)

  const hidden = useMemo(() => new Set(backrefs.map((b) => b.field)), [backrefs])
  const cols = useMemo(() => backrefColumns(col, backrefs), [col, backrefs])

  const prefill = new URLSearchParams()
  // prefill the new record with the reference to this one
  const ref = (col.refs ?? []).find((r) => hidden.has(r.field))
  if (ref) {
    const v = parent.data[ref.toField]
    if (v !== undefined) prefill.set(ref.field, str(v))
  }

  const { view: shownRecord } = edit
  const matching = useMemo(
    () => filterRows(records, (r) => cols.map((c) => str(shownRecord(r).data[c])).join('\n'), q),
    [records, cols, q, shownRecord],
  )
  const view = paginate(matching, page, size)

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <div className="relative min-w-0 flex-1 sm:max-w-72">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => {
              setQ(e.target.value)
              setPage(1)
            }}
            placeholder={t.show.searchPlaceholder}
            aria-label={t.show.searchPlaceholder}
            className="h-8 pl-8"
          />
        </div>
        <label className="flex items-center gap-1.5 text-xs whitespace-nowrap text-muted-foreground">
          {t.show.perPage}
          <NativeSelect
            value={size}
            onChange={(e) => {
              setSize(Number(e.target.value))
              setPage(1)
            }}
            className="h-8 w-20 text-sm"
          >
            {PAGE_SIZES.map((n) => (
              <option key={n} value={n}>
                {n === 0 ? t.show.pageAll : n}
              </option>
            ))}
          </NativeSelect>
        </label>
        {editable && !generic && (
          <Button size="sm" variant="outline" className="ml-auto" render={<Link to={`/c/${encodeURIComponent(col.name)}/-/new${prefill.size ? `?${prefill}` : ''}`} />}>
            <Plus /> {t.show.addRelated}
          </Button>
        )}
      </div>
      {generic && <p className="mb-3 text-xs text-muted-foreground">{t.show.genericNote}</p>}

      {records.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t.show.backrefsEmpty}</p>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full border-collapse text-sm">
              <thead className="bg-muted/60">
                <tr className="border-b">
                  {cols.map((c) => (
                    <th key={c} scope="col" className="h-9 px-3 text-left text-xs font-semibold tracking-wide whitespace-nowrap text-muted-foreground">
                      {fieldTitle(col, c)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {view.items.map((r, ri) => {
                  const href = recordHref(col.name, r.id)
                  const shown = edit.view(r)
                  return (
                    <tr key={r.id} className={rowClass} {...rowNav(href, ri === 0)}>
                      {cols.map((c, i) => (
                        <td key={c} className="px-3 py-2.5 align-top">
                          {i === 0 && !lookups[c] ? (
                            <Link to={href} title={str(shown.data[c])} className={cn('line-clamp-2 max-w-[44ch] font-medium break-words hover:underline', looksMono(str(shown.data[c])) && 'font-mono text-[0.8125rem]')}>
                              {str(shown.data[c]) || t.show.empty}
                            </Link>
                          ) : (
                            <RecordCell col={col} rec={r} field={c} lookup={lookups[c]} edit={editable ? edit : undefined} />
                          )}
                        </td>
                      ))}
                    </tr>
                  )
                })}
                {view.total === 0 && (
                  <tr>
                    <td colSpan={Math.max(cols.length, 1)} className="py-8 text-center text-muted-foreground">
                      {t.show.noMatch}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground tabular-nums">
            <span>{t.show.pageRange(view.from, view.to, view.total, records.length)}</span>
            {view.pages > 1 && (
              <span className="flex items-center gap-1">
                <Button variant="outline" size="icon-sm" aria-label={t.show.prevPage} disabled={view.page <= 1} onClick={() => setPage(view.page - 1)}>
                  <ChevronLeft />
                </Button>
                <span className="px-1">
                  {view.page} / {view.pages}
                </span>
                <Button variant="outline" size="icon-sm" aria-label={t.show.nextPage} disabled={view.page >= view.pages} onClick={() => setPage(view.page + 1)}>
                  <ChevronRight />
                </Button>
              </span>
            )}
          </div>
        </>
      )}
    </div>
  )
}
