import type { useInlineEdit } from '@/hooks/use-inline-edit'
import type { RefLookup } from '@/lib/hooks'
import { inlineKind } from '@/lib/fieldKind'
import { fieldTitle, moduleFor } from '@/lib/ledger'
import type { Collection, LedgerRecord } from '@/lib/types'
import { useMeta } from '@/providers/meta'
import { CellValue } from './CellValue'
import { InlineCell } from './InlineCell'

export type InlineEdit = ReturnType<typeof useInlineEdit>

/**
 * One cell of a record table. With `edit` (the user may edit) an enum, boolean, date
 * or array-of-enum field edits in place; everything else is shown as before.
 */
export function RecordCell({
  col,
  rec,
  field,
  lookup,
  edit,
}: {
  col: Collection
  rec: LedgerRecord
  field: string
  lookup?: RefLookup
  edit?: InlineEdit
}) {
  const { meta } = useMeta()
  const shown = edit ? edit.view(rec) : rec
  const value = shown.data[field]
  const prop = col.schema.properties?.[field]
  const kind =
    edit && !lookup
      ? inlineKind(prop, { isKey: !!col.key?.includes(field), isRef: !!col.refs?.some((r) => r.field === field) })
      : null
  // a module maintains these fields: the edit form warns about it, a quick edit should not bypass that
  const managed = kind ? moduleFor(meta, col.name, shown.data.source)?.fields.includes(field) : false
  if (!edit || !kind || !prop || managed) return <CellValue value={value} lookup={lookup} schema={prop} />
  return (
    <InlineCell
      kind={kind}
      prop={prop}
      value={value}
      label={fieldTitle(col, field)}
      required={!!col.schema.required?.includes(field)}
      version={shown.hash}
      busy={edit.isSaving(rec.id)}
      onSave={(v) => void edit.save(rec, field, v)}
    />
  )
}
