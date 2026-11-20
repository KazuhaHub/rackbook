import { ArrowDown, ArrowUp, KeyRound, Pencil, Plus, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/common'
import { t } from '@/i18n'
import { fieldTypeLabel, type TypeDef } from '@/lib/typedef'

const dot = <span className="text-primary">●</span>

export function FieldsTab({
  draft,
  update,
  onEdit,
  onAdd,
  onRemove,
}: {
  draft: TypeDef
  update: (fn: (d: TypeDef) => TypeDef) => void
  onEdit: (name: string) => void
  onAdd: () => void
  onRemove: (name: string) => void
}) {
  const move = (i: number, by: -1 | 1) =>
    update((d) => {
      const fields = [...d.fields]
      ;[fields[i], fields[i + by]] = [fields[i + by], fields[i]]
      return { ...d, fields }
    })

  if (draft.fields.length === 0) {
    return (
      <EmptyState
        title={t.types.fields.empty}
        body={t.types.fields.emptyHint}
        action={
          <Button onClick={onAdd}>
            <Plus /> {t.types.fields.add}
          </Button>
        }
      />
    )
  }
  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-xl border">
        <table className="w-full border-collapse text-sm">
          <thead className="bg-muted/60 text-xs tracking-wide text-muted-foreground">
            <tr className="border-b">
              {[t.types.fields.name, t.types.fields.title, t.types.fields.type, t.types.fields.required, t.types.fields.unique, t.types.fields.list, t.types.fields.facet].map((h) => (
                <th key={h} className="h-9 px-3 text-left font-semibold whitespace-nowrap">
                  {h}
                </th>
              ))}
              <th className="w-px" />
            </tr>
          </thead>
          <tbody>
            {draft.fields.map((f, i) => (
              <tr key={f.name || `new-${i}`} style={{ '--i': i } as React.CSSProperties} className="rb-row-in border-b transition-colors last:border-0 hover:bg-muted/30">
                  <td className="px-3 py-2">
                    <button type="button" className="flex items-center gap-1.5 font-mono text-[0.8125rem] hover:underline" onClick={() => onEdit(f.name)}>
                      {f.name}
                      {draft.key.includes(f.name) && <KeyRound className="size-3 text-muted-foreground" aria-label={t.types.fields.inKey} />}
                    </button>
                  </td>
                  <td className="px-3 py-2">{f.title || <span className="text-muted-foreground">—</span>}</td>
                  <td className="px-3 py-2">
                    <span className="flex flex-wrap items-center gap-1.5">
                      <Badge variant="secondary">{fieldTypeLabel(f.type)}</Badge>
                      {f.type === 'ref' && f.ref && <span className="font-mono text-xs text-muted-foreground">→ {f.ref.to}.{f.ref.toField}</span>}
                      {f.advanced && <Badge variant="outline" title={t.types.fields.advancedHint}>{t.types.fields.advanced}</Badge>}
                    </span>
                  </td>
                  <td className="px-3 py-2">{f.required ? dot : ''}</td>
                  <td className="px-3 py-2">{f.unique ? dot : ''}</td>
                  <td className="px-3 py-2">{draft.list.includes(f.name) ? dot : ''}</td>
                  <td className="px-3 py-2">{draft.facets.some((x) => x.field === f.name) ? dot : ''}</td>
                  <td className="px-2 py-1.5 whitespace-nowrap">
                    <Button variant="ghost" size="icon-sm" aria-label={t.types.fields.moveUp} disabled={i === 0} onClick={() => move(i, -1)}>
                      <ArrowUp />
                    </Button>
                    <Button variant="ghost" size="icon-sm" aria-label={t.types.fields.moveDown} disabled={i === draft.fields.length - 1} onClick={() => move(i, 1)}>
                      <ArrowDown />
                    </Button>
                    <Button variant="ghost" size="icon-sm" aria-label={t.types.fields.edit} onClick={() => onEdit(f.name)}>
                      <Pencil />
                    </Button>
                    <Button variant="ghost" size="icon-sm" aria-label={t.types.fields.remove} onClick={() => onRemove(f.name)}>
                      <Trash2 />
                    </Button>
                  </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Button variant="outline" onClick={onAdd}>
        <Plus /> {t.types.fields.add}
      </Button>
    </div>
  )
}
