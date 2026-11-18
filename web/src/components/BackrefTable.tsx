import { Link, useNavigate } from 'react-router'
import { Plus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { t } from '@/i18n/zh-CN'
import { defaultColumns, fieldTitle, recordHref, str } from '@/lib/ledger'
import type { Backref, Collection, LedgerRecord } from '@/lib/types'
import { CellValue } from './CellValue'
import { useRefLookups } from '@/lib/hooks'

/** Records of another collection that reference the one on screen. */
export function BackrefTable({
  col,
  backrefs,
  records,
  parent,
  editable,
}: {
  col: Collection
  backrefs: Backref[]
  records: LedgerRecord[]
  parent: LedgerRecord
  editable: boolean
}) {
  const navigate = useNavigate()
  const lookups = useRefLookups(col)
  // Hide the referencing field(s): it is the record the user is already on.
  const hidden = new Set(backrefs.map((b) => b.field))
  const cols = defaultColumns(col).filter((c) => !hidden.has(c))
  const prefill = new URLSearchParams()
  // prefill the new record with the reference to this one
  const ref = (col.refs ?? []).find((r) => hidden.has(r.field))
  if (ref) {
    const src = ref.toField
    const v = parent.data[src]
    if (v !== undefined) prefill.set(ref.field, str(v))
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {col.title}
          <Badge variant="secondary">{records.length}</Badge>
        </CardTitle>
        {editable && (
          <CardAction>
          <Button
            size="sm"
            variant="outline"
            render={<Link to={`/c/${encodeURIComponent(col.name)}/-/new${prefill.size ? `?${prefill}` : ''}`} />}
          >
            <Plus /> {t.show.addRelated}
          </Button>
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        {records.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t.show.backrefsEmpty}</p>
        ) : (
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full border-collapse text-sm">
              <thead className="bg-muted/60">
                <tr className="border-b">
                  {cols.map((c) => (
                    <th key={c} className="h-8 px-3 text-left text-xs font-medium whitespace-nowrap text-muted-foreground">
                      {fieldTitle(col, c)}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {records.map((r) => {
                  const href = recordHref(col.name, r.id)
                  // e.g. services with `device: all` apply to every device
                  const generic = backrefs.some((b) => {
                    const ref = (col.refs ?? []).find((x) => x.field === b.field)
                    return ref && str(r.data[b.field]) !== str(parent.data[ref.toField]) && (ref.allow ?? []).includes(str(r.data[b.field]))
                  })
                  return (
                    <tr
                      key={r.id}
                      className="cursor-pointer border-b last:border-0 hover:bg-muted/50"
                      onClick={(e) => {
                        if (!(e.target as HTMLElement).closest('a,button')) navigate(href)
                      }}
                    >
                      {cols.map((c, i) => (
                        <td key={c} className="px-3 py-2 align-top">
                          {i === 0 && !lookups[c] ? (
                            <span className="flex flex-wrap items-center gap-2">
                              <Link to={href} className="font-medium hover:underline">
                                <CellValue value={r.data[c]} variant="detail" />
                              </Link>
                              {generic && <Badge variant="secondary">{t.show.allDevices}</Badge>}
                            </span>
                          ) : (
                            <CellValue value={r.data[c]} lookup={lookups[c]} variant="detail" />
                          )}
                        </td>
                      ))}
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
