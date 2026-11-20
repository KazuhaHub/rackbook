import { Link } from 'react-router'
import { ArrowRight, Pencil, Plus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { t } from '@/i18n'
import type { TypeDef } from '@/lib/typedef'
import { useMeta } from '@/providers/meta'

export function RelationsTab({
  draft,
  incoming,
  onEdit,
  onAddRef,
}: {
  draft: TypeDef
  incoming: { collection: string; field: string; title?: string }[]
  onEdit: (name: string) => void
  onAddRef: () => void
}) {
  const { byName } = useMeta()
  const refs = draft.fields.filter((f) => f.ref)
  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle>{t.types.relations.outgoing}</CardTitle>
          <CardDescription>{t.types.relations.outgoingHint}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {refs.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t.types.relations.noOutgoing}</p>
          ) : (
            <ul className="divide-y rounded-lg border">
              {refs.map((f) => (
                <li key={f.name} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
                  <span className="font-mono text-[0.8125rem]">{draft.name}.{f.name}</span>
                  <ArrowRight className="size-3.5 text-muted-foreground" />
                  <span className="font-mono text-[0.8125rem]">{f.ref!.to}.{f.ref!.toField}</span>
                  <Badge variant="secondary">{f.ref!.many ? t.types.relations.many : t.types.relations.single}</Badge>
                  {(f.ref!.allow ?? []).map((a) => (
                    <Badge key={a} variant="outline" className="font-mono" title={t.types.relations.allow}>
                      {a}
                    </Badge>
                  ))}
                  {f.ref!.backrefTitle && <span className="text-xs text-muted-foreground">{t.types.relations.backTitle}{t.common.colon}{f.ref!.backrefTitle}</span>}
                  <Button className="ml-auto" variant="ghost" size="icon-sm" aria-label={t.types.fields.edit} onClick={() => onEdit(f.name)}>
                    <Pencil />
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <Button variant="outline" onClick={onAddRef}>
            <Plus /> {t.types.relations.addRef}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t.types.relations.incoming}</CardTitle>
          <CardDescription>{t.types.relations.incomingHint}</CardDescription>
        </CardHeader>
        <CardContent>
          {incoming.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t.types.relations.noIncoming}</p>
          ) : (
            <ul className="divide-y rounded-lg border">
              {incoming.map((b) => (
                <li key={`${b.collection}.${b.field}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2.5 text-sm">
                  <span className="font-mono text-[0.8125rem]">{b.collection}.{b.field}</span>
                  <ArrowRight className="size-3.5 text-muted-foreground" />
                  <span className="font-mono text-[0.8125rem]">{draft.name}</span>
                  {b.title && <span className="text-xs text-muted-foreground">{b.title}</span>}
                  {byName.has(b.collection) && (
                    <Link to={`/types/${encodeURIComponent(b.collection)}`} className="ml-auto text-xs text-brand hover:underline">
                      {t.types.relations.open} {byName.get(b.collection)!.title}
                    </Link>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
