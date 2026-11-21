import { useMemo, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Skeleton } from '@/components/ui/skeleton'
import { EmptyState } from '@/components/common'
import { InfraFrame, LoadError } from '@/components/infra/InfraFrame'
import { EditResult, ReauthNotice } from '@/components/infra/EditReview'
import { t } from '@/i18n'
import { useEditFlow, useInfraGroups, useWriteState, type InventoryFile } from '@/lib/infraEdit'
import { useMeta } from '@/providers/meta'

const k = (host: string, group: string) => `${host}\u0000${group}`

function GroupsEditor({ data, onReload }: { data: InventoryFile; onReload: () => void }) {
  const flow = useEditFlow()
  const m = data.membership
  const initial = useMemo(() => {
    const s = new Set<string>()
    for (const [h, gs] of Object.entries(m.direct)) for (const g of gs) s.add(k(h, g))
    return s
  }, [m])
  const [now, setNow] = useState<Set<string>>(() => new Set(initial))
  const changes = useMemo(() => {
    const out: { host: string; group: string; member: boolean }[] = []
    for (const h of m.hosts) for (const g of m.groups) if (initial.has(k(h, g)) !== now.has(k(h, g))) out.push({ host: h, group: g, member: now.has(k(h, g)) })
    return out
  }, [m, initial, now])
  const busy = flow.state.phase === 'checking' || flow.state.phase === 'committing'
  return (
    <>
      {m.groups.length === 0 ? (
        <EmptyState title={t.infra.edit.groups.none} />
      ) : (
        <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/60">
              <tr className="border-b text-left text-xs text-muted-foreground">
                <th className="h-10 px-4 font-semibold">{t.infra.edit.groups.host}</th>
                {m.groups.map((g) => (
                  <th key={g} className="h-10 px-3 text-center font-mono font-semibold whitespace-nowrap">
                    {g}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {m.hosts.map((h) => (
                <tr key={h} className="border-b last:border-0">
                  <td className="px-4 py-2 font-mono text-xs break-all">{h}</td>
                  {m.groups.map((g) => (
                    <td key={g} className="px-3 py-2 text-center">
                      <Checkbox
                        aria-label={`${h} / ${g}`}
                        checked={now.has(k(h, g))}
                        onCheckedChange={(v) =>
                          setNow((s) => {
                            const n = new Set(s)
                            if (v) n.add(k(h, g))
                            else n.delete(k(h, g))
                            return n
                          })
                        }
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="mt-3 flex items-center gap-3">
        <Button disabled={busy || changes.length === 0} onClick={() => flow.review('groups', '/infra/groups', { base: data.base, changes })}>
          {t.infra.edit.review}
        </Button>
        <span className="text-xs text-muted-foreground">{t.infra.edit.groups.changed(changes.length)}</span>
      </div>
      <EditResult flow={flow.state} mine={flow.state.key === 'groups'} onCommit={flow.commit} onReload={onReload} onCancel={flow.reset} />
    </>
  )
}

export default function InfraGroups() {
  const { meta } = useMeta()
  const canWrite = !!meta.user?.canInfraWrite
  const q = useInfraGroups(canWrite)
  const write = useWriteState(canWrite)
  return (
    <InfraFrame>
      {!canWrite ? (
        <EmptyState title={t.infra.edit.writeOff} />
      ) : q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : q.isError ? (
        <LoadError error={q.error} />
      ) : (
        <>
          <p className="mb-1 text-sm text-muted-foreground">{t.infra.edit.groups.hint}</p>
          <p className="mb-4 text-xs text-muted-foreground">{t.infra.edit.commitNote}</p>
          {write.data && !write.data.fresh && <ReauthNotice hours={Math.round(write.data.maxAgeSeconds / 3600)} />}
          <GroupsEditor key={q.data.base} data={q.data} onReload={() => void q.refetch()} />
        </>
      )}
    </InfraFrame>
  )
}
