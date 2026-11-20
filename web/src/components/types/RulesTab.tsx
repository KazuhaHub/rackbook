import { useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { t } from '@/i18n'
import type { TypeDef } from '@/lib/typedef'

export function RulesTab({ draft, update }: { draft: TypeDef; update: (fn: (d: TypeDef) => TypeDef) => void }) {
  const [adding, setAdding] = useState(false)
  const [pick, setPick] = useState<string[]>([])
  const names = draft.fields.map((f) => f.name).filter(Boolean)
  const refs = draft.fields.filter((f) => f.ref)
  const singles = draft.fields.filter((f) => f.unique)
  const addUnique = () => {
    update((d) => ({ ...d, unique: [...d.unique, pick] }))
    setPick([])
    setAdding(false)
  }
  const row = (badge: string, text: React.ReactNode, action?: React.ReactNode) => (
    <li className="flex items-center gap-3 px-3 py-2.5 text-sm">
      <Badge variant="secondary">{badge}</Badge>
      <span className="min-w-0 flex-1">{text}</span>
      {action}
    </li>
  )
  const empty = refs.length + singles.length + draft.unique.length + (draft.sameSet?.length ?? 0) === 0

  return (
    <div className="space-y-5">
      <p className="text-sm text-muted-foreground">{t.types.rules.intro}</p>
      <Card>
        <CardContent className="space-y-4 pt-4">
          {empty ? (
            <p className="text-sm text-muted-foreground">{t.types.rules.none}</p>
          ) : (
            <ul className="divide-y rounded-lg border">
              {refs.map((f) => row(t.types.rules.ref, <span className="font-mono text-[0.8125rem]">{t.types.rules.refRule(`${draft.name}.${f.name}`, `${f.ref!.to}.${f.ref!.toField}`)}</span>))}
              {singles.map((f) => row(t.types.rules.unique, <span className="font-mono text-[0.8125rem]">{t.types.rules.uniqueField(f.name)}</span>))}
              {draft.unique.map((u, i) =>
                row(
                  t.types.rules.unique,
                  <span className="font-mono text-[0.8125rem]">{t.types.rules.uniqueRule(u.join(' + '))}</span>,
                  <Button variant="ghost" size="icon-sm" aria-label={t.types.rules.remove} onClick={() => update((d) => ({ ...d, unique: d.unique.filter((_, j) => j !== i) }))}>
                    <Trash2 />
                  </Button>,
                ),
              )}
            </ul>
          )}
          {adding ? (
            <div className="space-y-3 rounded-lg border p-3">
              <p className="text-sm">{t.types.rules.pickUnique}</p>
              <div className="flex flex-wrap gap-x-5 gap-y-2">
                {names.map((n) => (
                  <label key={n} className="flex items-center gap-2 text-sm">
                    <Checkbox checked={pick.includes(n)} onCheckedChange={(v) => setPick(v ? [...pick, n] : pick.filter((x) => x !== n))} />
                    <span className="font-mono">{n}</span>
                  </label>
                ))}
              </div>
              <div className="flex gap-2">
                <Button size="sm" disabled={pick.length < 2} onClick={addUnique}>
                  {t.types.rules.add}
                </Button>
                <Button size="sm" variant="outline" onClick={() => { setAdding(false); setPick([]) }}>
                  {t.types.dialog.cancel}
                </Button>
              </div>
            </div>
          ) : (
            <Button variant="outline" onClick={() => setAdding(true)} disabled={names.length < 2}>
              <Plus /> {t.types.rules.addUnique}
            </Button>
          )}
        </CardContent>
      </Card>

      {(draft.sameSet?.length ?? 0) > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>{t.types.rules.sameSet}</CardTitle>
            <CardDescription>{t.types.rules.sameSetHint}</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y rounded-lg border">
              {draft.sameSet!.map((s, i) => (
                <li key={i} className="space-y-0.5 px-3 py-2.5 text-sm">
                  <div className="font-mono text-[0.8125rem]">{s.left} = {s.right}</div>
                  {s.message && <div className="text-xs text-muted-foreground">{s.message}</div>}
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
