import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import { useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Eye, EyeOff, KeyRound, RefreshCw, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { EmptyState } from '@/components/common'
import { InfraFrame, LoadError } from '@/components/infra/InfraFrame'
import { EditResult, ReauthNotice } from '@/components/infra/EditReview'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { ApiError, apiFetch } from '@/lib/api'
import { problemOf, useSecrets, useWriteState, type FlowState, type Outcome, type SecretKey } from '@/lib/infraEdit'
import { useMeta } from '@/providers/meta'

/** A shown value goes away after this long, and with the page. */
const REVEAL_MS = 30_000
const keyRe = /^[a-z0-9_-]{1,128}$/

const keyOk = (k: string) => keyRe.test(k) && k !== 'sops' && !k.endsWith('_unencrypted')

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <div className="mb-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <h2 className="text-base font-semibold">{title}</h2>
        {hint && <span className="text-xs text-muted-foreground">{hint}</span>}
      </div>
      {children}
    </section>
  )
}

export default function InfraSecrets() {
  const { name = '' } = useParams()
  const { meta } = useMeta()
  const canWrite = !!meta.user?.canInfraWrite
  const qc = useQueryClient()
  const write = useWriteState(canWrite)
  const q = useSecrets(name, !!meta.user?.canInfra)
  const [flow, setFlow] = useState<FlowState>({ phase: 'idle' })
  const [busy, setBusy] = useState(false)
  // the value on screen: held in this component only, never in the query cache
  const [shown, setShown] = useState<{ key: string; value: string } | null>(null)
  const [revealProblem, setRevealProblem] = useState<{ key: string; message: string } | null>(null)
  const [editing, setEditing] = useState<string | null>(null)
  const [value, setValue] = useState('')
  const [newKey, setNewKey] = useState('')
  const [newValue, setNewValue] = useState('')
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const hide = () => {
    clearTimeout(timer.current)
    setShown(null)
  }
  useEffect(() => () => clearTimeout(timer.current), [])

  const base = '/infra/hosts/' + encodeURIComponent(name) + '/secrets'
  const stale = write.data && !write.data.fresh
  const notFound = q.error instanceof ApiError && q.error.statusCode === 404
  const file = q.data?.file
  const writable = !!q.data?.canWrite && !!file && (file.canDecrypt || !file.exists)
  // re-encrypting needs the file, a rule to follow and this server's key to read it
  const canReencrypt = !!q.data?.canWrite && !!file && file.exists && !file.problem && file.canDecrypt && !!file.rule && file.rule.length > 0
  const recipientsDiffer = !!file?.rule && [...file.recipients].sort().join(',') !== [...file.rule].sort().join(',')

  const reveal = async (key: string) => {
    hide()
    setRevealProblem(null)
    setBusy(true)
    try {
      const r = await apiFetch<{ key: string; value: string }>(`${base}/reveal`, { method: 'POST', body: JSON.stringify({ key }) })
      setShown({ key: r.key, value: r.value })
      timer.current = setTimeout(() => setShown(null), REVEAL_MS)
    } catch (e) {
      const p = problemOf(e)
      setRevealProblem({ key, message: p.kind === 'message' ? p.message : p.kind === 'reauth' ? t.infra.edit.reauth.title : t.infra.edit.failed })
    } finally {
      setBusy(false)
    }
  }

  const change = async (action: 'set' | 'unset', key: string, val: string) => {
    if (!file) return
    hide()
    setBusy(true)
    setFlow({ phase: 'committing', key })
    try {
      const outcome = await apiFetch<Outcome>(`${base}/${action}`, { method: 'POST', body: JSON.stringify({ base: file.base, key, value: val }) })
      setFlow({ phase: 'done', key, outcome })
      setEditing(null)
      setValue('')
      if (action === 'set' && key === newKey) {
        setNewKey('')
        setNewValue('')
      }
      await qc.invalidateQueries({ queryKey: ['rb', 'infra'] })
    } catch (e) {
      setFlow({ phase: 'idle', key, problem: problemOf(e) })
    } finally {
      setBusy(false)
    }
  }

  const reencrypt = async () => {
    if (!file) return
    hide()
    setBusy(true)
    setFlow({ phase: 'committing', key: 'reencrypt' })
    try {
      const outcome = await apiFetch<Outcome>(`${base}/reencrypt`, { method: 'POST', body: JSON.stringify({ base: file.base }) })
      setFlow({ phase: 'done', key: 'reencrypt', outcome })
      await qc.invalidateQueries({ queryKey: ['rb', 'infra'] })
    } catch (e) {
      setFlow({ phase: 'idle', key: 'reencrypt', problem: problemOf(e) })
    } finally {
      setBusy(false)
    }
  }

  const reload = () => {
    setFlow({ phase: 'idle' })
    void q.refetch()
  }
  const noop = () => {}

  const row = (k: SecretKey) => (
    <tr key={k.name} className="border-b align-top last:border-0">
      <td className="px-4 py-2.5 font-mono text-xs break-all">{k.name}</td>
      <td className="px-4 py-2.5">
        {shown?.key === k.name && (
          <div className="flex flex-wrap items-center gap-2">
            <code className="rounded bg-muted px-2 py-1 font-mono text-xs break-all whitespace-pre-wrap">{shown.value}</code>
            <Button size="xs" variant="outline" onClick={hide}>
              <EyeOff /> {t.infra.secrets.hide}
            </Button>
          </div>
        )}
        {revealProblem?.key === k.name && (
          <p role="alert" className="text-xs text-destructive">
            {revealProblem.message}
          </p>
        )}
        {editing === k.name && (
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault()
              void change('set', k.name, value)
            }}
          >
            <Textarea autoComplete="off" spellCheck={false} rows={4} aria-label={t.infra.secrets.newValueFor(k.name)} value={value} onChange={(e) => setValue(e.target.value)} className="w-full max-w-md font-mono text-xs" />
            <Button size="xs" type="submit" disabled={busy || value === ''}>
              {t.infra.secrets.save}
            </Button>
            <Button size="xs" type="button" variant="outline" onClick={() => (setEditing(null), setValue(''))}>
              {t.infra.edit.back2}
            </Button>
          </form>
        )}
      </td>
      <td className="px-4 py-2.5 text-right whitespace-nowrap">
        {k.editable ? (
          <div className="flex justify-end gap-2">
            {file?.canDecrypt && (
              <Button size="xs" variant="outline" disabled={busy || !!stale} onClick={() => void reveal(k.name)}>
                <Eye /> {t.infra.secrets.reveal}
              </Button>
            )}
            {writable && (
              <>
                <Button size="xs" variant="outline" disabled={busy || !!stale} onClick={() => (hide(), setEditing(k.name), setValue(''))}>
                  {t.infra.secrets.replace}
                </Button>
                <Button
                  size="xs"
                  variant="outline"
                  disabled={busy || !!stale}
                  onClick={() => {
                    if (window.confirm(t.infra.secrets.confirmDelete(k.name))) void change('unset', k.name, '')
                  }}
                >
                  <Trash2 /> {t.infra.secrets.delete}
                </Button>
              </>
            )}
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">{t.infra.secrets.notEditable}</span>
        )}
      </td>
    </tr>
  )

  return (
    <InfraFrame header={false}>
      <Link to={`/infra/hosts/${encodeURIComponent(name)}`} className="mb-4 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-4" /> {t.infra.edit.back}
      </Link>
      <h1 className="mb-2 text-xl font-semibold break-all">{t.infra.secrets.title(name)}</h1>
      {q.isPending ? (
        <Skeleton className="h-40 w-full" />
      ) : notFound ? (
        <EmptyState title={t.infra.host.notFound} />
      ) : q.isError ? (
        <LoadError error={q.error} />
      ) : !q.data.enabled || !file ? (
        <EmptyState icon={<KeyRound />} title={t.infra.secrets.off} body={t.infra.secrets.offBody} />
      ) : (
        <>
          <p className="mb-4 text-xs text-muted-foreground">{t.infra.secrets.note}</p>
          {stale && <ReauthNotice hours={Math.round((write.data?.maxAgeSeconds ?? 43200) / 3600)} />}

          <Section title={t.infra.secrets.fileTitle} hint={file.path}>
            <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              <div>
                <dt className="text-xs text-muted-foreground">{t.infra.secrets.status}</dt>
                <dd className="mt-0.5 text-sm">
                  {!file.exists ? (
                    <Badge variant="outline">{t.infra.secrets.noFile}</Badge>
                  ) : file.problem ? (
                    <Badge variant="destructive">{t.infra.secrets.unreadable}</Badge>
                  ) : file.canDecrypt ? (
                    <Badge variant="secondary">{t.infra.secrets.canDecrypt}</Badge>
                  ) : (
                    <Badge variant="destructive">{t.infra.secrets.cannotDecrypt}</Badge>
                  )}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">{t.infra.secrets.recipients}</dt>
                <dd className="mt-0.5 text-sm">{file.recipients.length}</dd>
              </div>
              {file.lastModified && (
                <div>
                  <dt className="text-xs text-muted-foreground">{t.infra.secrets.modified}</dt>
                  <dd className="mt-0.5 text-sm">{formatDateTime(file.lastModified)}</dd>
                </div>
              )}
            </dl>
            {file.exists && !file.canDecrypt && !file.problem && <p className="mt-3 text-sm text-muted-foreground">{t.infra.secrets.cannotDecryptHelp}</p>}
            <div className="mt-4 rounded-lg border bg-muted/30 px-3 py-2">
              <p className="text-xs text-muted-foreground">{t.infra.secrets.publicKey}</p>
              <p className="mt-1 font-mono text-xs break-all select-all">{q.data.publicKey}</p>
              <p className="mt-1 text-xs text-muted-foreground">{t.infra.secrets.publicKeyHelp}</p>
            </div>
          </Section>

          <Section title={t.infra.secrets.keysTitle} hint={t.infra.secrets.keysHint}>
            {file.keys.length === 0 ? (
              <p className="text-sm text-muted-foreground">{t.infra.secrets.noKeys}</p>
            ) : (
              <div className="overflow-x-auto rounded-xl border bg-card shadow-xs">
                <table className="w-full border-collapse text-sm">
                  <thead className="bg-muted/60">
                    <tr className="border-b text-left text-xs text-muted-foreground">
                      <th className="h-10 px-4 font-semibold">{t.infra.secrets.columns.key}</th>
                      <th className="h-10 px-4 font-semibold">{t.infra.secrets.columns.value}</th>
                      <th className="h-10 px-4" />
                    </tr>
                  </thead>
                  <tbody>{file.keys.map(row)}</tbody>
                </table>
              </div>
            )}
          </Section>

          {canReencrypt && (
            <Section title={t.infra.secrets.reencryptTitle}>
              {recipientsDiffer ? (
                <p role="status" className="mb-3 rounded-lg border border-destructive/40 bg-destructive/5 px-3 py-2 text-sm">
                  {t.infra.secrets.reencryptDiffer}
                </p>
              ) : (
                <p className="mb-3 text-sm text-muted-foreground">{t.infra.secrets.reencryptSame}</p>
              )}
              <Button
                variant={recipientsDiffer ? 'default' : 'outline'}
                disabled={busy || !!stale}
                onClick={() => {
                  if (window.confirm(t.infra.secrets.confirmReencrypt)) void reencrypt()
                }}
              >
                <RefreshCw /> {t.infra.secrets.reencrypt}
              </Button>
            </Section>
          )}

          {writable && (
            <Section title={t.infra.secrets.addTitle} hint={t.infra.secrets.addHint}>
              <form
                className="grid max-w-xl gap-3"
                onSubmit={(e) => {
                  e.preventDefault()
                  void change('set', newKey, newValue)
                }}
              >
                <div className="space-y-1">
                  <Label htmlFor="secret-key">{t.infra.secrets.columns.key}</Label>
                  <Input id="secret-key" value={newKey} onChange={(e) => setNewKey(e.target.value)} placeholder="feature_name_setting" className="font-mono" autoComplete="off" spellCheck={false} />
                  {newKey !== '' && !keyOk(newKey) && <p className="text-xs text-destructive">{t.infra.secrets.keyRule}</p>}
                </div>
                <div className="space-y-1">
                  <Label htmlFor="secret-value">{t.infra.secrets.columns.value}</Label>
                  <Textarea id="secret-value" autoComplete="off" spellCheck={false} rows={4} value={newValue} onChange={(e) => setNewValue(e.target.value)} className="font-mono text-xs" />
                </div>
                <div>
                  <Button type="submit" disabled={busy || !!stale || !keyOk(newKey) || newValue === ''}>
                    {t.infra.secrets.save}
                  </Button>
                </div>
              </form>
            </Section>
          )}
          <EditResult flow={flow} mine={flow.key !== undefined} onCommit={noop} onReload={reload} onCancel={() => setFlow({ phase: 'idle' })} />
        </>
      )}
    </InfraFrame>
  )
}
