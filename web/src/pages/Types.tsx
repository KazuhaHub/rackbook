import { Link, useNavigate } from 'react-router'
import { Plus, ShieldAlert } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { CollectionIcon } from '@/components/CollectionIcon'
import { EmptyState, PageHeader } from '@/components/common'
import { t } from '@/i18n/zh-CN'
import { errorMessage } from '@/lib/api'
import { useTypeList } from '@/lib/typesApi'
import { useMeta } from '@/providers/meta'

export default function Types() {
  const { meta } = useMeta()
  const admin = !!meta.user?.canAdmin
  const q = useTypeList(admin)
  const navigate = useNavigate()
  if (!admin) {
    return <EmptyState icon={<ShieldAlert />} title={t.types.adminOnly} />
  }
  return (
    <div>
      <PageHeader
        title={t.types.title}
        description={t.types.subtitle}
        actions={
          !meta.readOnly && (
            <Button render={<Link to="/types/-/new" />}>
              <Plus /> {t.types.create}
            </Button>
          )
        }
      />
      {q.isPending ? (
        <Skeleton className="h-64 w-full" />
      ) : q.isError ? (
        <EmptyState title={t.errors.generic} body={errorMessage(q.error)} />
      ) : q.data.types.length === 0 ? (
        <EmptyState title={t.types.noTypes} />
      ) : (
        <div className="overflow-x-auto rounded-xl border">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60 text-xs tracking-wide text-muted-foreground">
              <tr className="border-b">
                {[t.types.basic.title, t.types.columns.group, t.types.columns.records, '字段', t.types.columns.file, t.types.columns.schema].map((h) => (
                  <th key={h} className="h-9 px-3 text-left font-semibold whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {q.data.types.map((ty, i) => (
                <tr
                  key={ty.name}
                  style={{ '--i': i } as React.CSSProperties}
                  className="rb-row-in cursor-pointer border-b transition-colors duration-150 last:border-0 hover:bg-brand/[0.07]"
                  onClick={(e) => {
                    if (!(e.target as HTMLElement).closest('a,button')) navigate(`/types/${encodeURIComponent(ty.name)}`)
                  }}
                >
                  <td className="px-3 py-2.5">
                    <Link to={`/types/${encodeURIComponent(ty.name)}`} className="flex items-center gap-2.5 font-medium hover:underline">
                      <CollectionIcon col={ty} className="size-4 text-muted-foreground" />
                      <span>
                        {ty.title}
                        <span className="ml-2 font-mono text-xs font-normal text-muted-foreground">{ty.name}</span>
                      </span>
                      {ty.problems > 0 && <Badge variant="destructive">{t.check.problems(ty.problems)}</Badge>}
                    </Link>
                  </td>
                  <td className="px-3 py-2.5 text-muted-foreground">{ty.group || t.types.ungrouped}</td>
                  <td className="px-3 py-2.5 tabular-nums">{ty.count}</td>
                  <td className="px-3 py-2.5 tabular-nums">{ty.fields}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">
                    {ty.file}
                    {ty.path && <span className="text-foreground"> :{ty.path}</span>}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-xs text-muted-foreground">{ty.schemaFile}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
