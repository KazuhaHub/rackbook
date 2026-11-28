import { useMemo, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowRightLeft, CircleAlert, ExternalLink, GitPullRequest, Info, Plus, RotateCcw, ShieldAlert, TriangleAlert, X } from 'lucide-react'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { Skeleton } from '@/components/ui/skeleton'
import { DiffView } from '@/components/types/DiffView'
import { EmptyState } from '@/components/common'
import { roleLabel } from '@/components/layout/UserMenu'
import { t } from '@/i18n'
import { ApiError, errorMessage } from '@/lib/api'
import {
  previewRoles,
  rolesKey,
  saveRoles,
  useRoles,
  viewDraft,
  viewEntries,
  type EntryNote,
  type RoleEntry,
  type RolesCap,
  type RolesPreview,
  type RolesView,
} from '@/lib/rolesApi'
import {
  ADD_KINDS,
  LISTS,
  ROLE_LISTS,
  addEntry,
  buildEntry,
  draftChanges,
  entryKey,
  hasEntry,
  kindOf,
  moveEntry,
  removeEntry,
  sameDraft,
  type Draft,
  type EntryKind,
  type ListName,
} from '@/lib/rolesDraft'
import { useMeta } from '@/providers/meta'

/** The words for one note of an entry, in the current language. */
function noteText(n: EntryNote): string {
  const R = t.auth.rolesEditor
  if (n.code === 'also_in') return R.alsoIn(R.lists[n.also as ListName] ?? n.also ?? '')
  if (n.code === 'invalid') return `${R.notes.invalid}${t.common.colon}${n.message}`
  return R.notes[n.code] ?? n.message
}

/** "Admin (by name)": the role and where it comes from. */
function capText(c: RolesCap): string {
  const R = t.auth.rolesEditor
  const from = c.roleFrom.map((k) => R.from[k] ?? k).join(t.common.clauseSep)
  const base = c.role === 'none' ? R.noAccess : roleLabel(c.role)
  const role = from && c.role !== 'none' ? `${base}${R.fromWrap(from)}` : base
  return c.auditor ? `${role}${R.andAuditor}` : role
}

function refusalText(code: string, fallback: string): string {
  const known = t.auth.rolesEditor.refusals[code]
  return known ?? fallback
}

/** The message of a failed request, by the code the server answered. */
function failureText(e: unknown): string {
  if (e instanceof ApiError) {
    const known = t.auth.rolesEditor.refusals[e.code]
    if (known) return known
    if (e.code === 'unsupported') return t.auth.rolesEditor.unsupported(e.message)
  }
  return errorMessage(e)
}

const kindIcon = (k: string) => (k === 'any' ? '*' : k === 'domain' ? '@' : k === 'group' ? '#' : k === 'app-role' ? '§' : k === 'oidc' ? 'ID' : k === 'mcphub' ? 'M' : k === 'oauth' ? 'O' : k === 'local' ? 'L' : '·')

function Chip({
  list,
  entry,
  isNew,
  disabled,
  onRemove,
  onMove,
}: {
  list: ListName
  entry: RoleEntry
  isNew: boolean
  disabled: boolean
  onRemove: () => void
  onMove: (to: ListName) => void
}) {
  const R = t.auth.rolesEditor
  const kind = entry.kind || kindOf(entry.value)
  const warn = entry.notes.filter((n) => n.level === 'warning')
  const errs = entry.notes.filter((n) => n.level === 'error')
  return (
    <li
      className={`flex items-start gap-2 rounded-lg border px-2.5 py-2 text-sm ${errs.length ? 'border-destructive/50 bg-destructive/5' : isNew ? 'border-brand/40 bg-brand/5' : 'bg-card'}`}
      data-testid="role-entry"
    >
      <span
        className="mt-0.5 flex h-5 min-w-5 shrink-0 items-center justify-center rounded bg-muted px-1 text-[0.65rem] font-semibold text-muted-foreground"
        title={kind ? R.kindHelp[kind] : undefined}
        aria-hidden="true"
      >
        {kindIcon(kind)}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="font-mono text-[0.8125rem] break-all">{entry.value || '—'}</span>
          {isNew && (
            <Badge variant="secondary" className="px-1.5 text-[0.65rem]">
              {R.newEntry}
            </Badge>
          )}
        </div>
        {kind && (
          <div className="text-xs text-muted-foreground">
            {R.kinds[kind]}
            {t.common.colon}
            {R.kindShort[kind]}
          </div>
        )}
        {[...errs, ...warn].map((n, i) => (
          <div key={i} className={`mt-0.5 flex items-start gap-1 text-xs ${n.level === 'error' ? 'text-destructive' : 'text-amber-700 dark:text-amber-400'}`}>
            {n.level === 'error' ? <CircleAlert className="mt-px size-3.5 shrink-0" /> : <TriangleAlert className="mt-px size-3.5 shrink-0" />}
            <span>{noteText(n)}</span>
          </div>
        ))}
      </div>
      <div className="flex shrink-0 items-center gap-0.5">
        {list !== 'auditors' && (
          <DropdownMenu>
            <DropdownMenuTrigger
              render={<Button variant="ghost" size="icon-xs" disabled={disabled} aria-label={`${R.moveTo}${t.common.colon}${entry.value}`} title={R.moveTo} />}
            >
              <ArrowRightLeft />
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              {ROLE_LISTS.filter((l) => l !== list).map((l) => (
                <DropdownMenuItem key={l} onClick={() => onMove(l)}>
                  {R.moveToList(R.lists[l])}
                </DropdownMenuItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
        <Button variant="ghost" size="icon-xs" disabled={disabled} aria-label={`${R.remove}${t.common.colon}${entry.value}`} title={R.remove} onClick={onRemove}>
          <X />
        </Button>
      </div>
    </li>
  )
}

function AddForm({ draft, disabled, sso, onAdd }: { draft: Draft; disabled: boolean; sso: boolean; onAdd: (list: ListName, value: string) => void }) {
  const R = t.auth.rolesEditor
  const [kind, setKind] = useState<EntryKind>('identity')
  const [text, setText] = useState('')
  const [list, setList] = useState<ListName>('viewer')
  const [error, setError] = useState('')
  const needsText = kind !== 'any'
  const submit = () => {
    const r = buildEntry(kind, text)
    if ('error' in r) return setError(R.addErrors[r.error])
    if (hasEntry(draft, list, r.value)) return setError(R.addErrors.duplicate)
    setError('')
    setText('')
    onAdd(list, r.value)
  }
  return (
    <form
      className="space-y-3 rounded-xl border bg-card p-4 shadow-xs"
      onSubmit={(e) => {
        e.preventDefault()
        submit()
      }}
    >
      <h3 className="text-sm font-semibold">{R.addTitle}</h3>
      <div className="grid gap-3 sm:grid-cols-[minmax(0,11rem)_minmax(0,1fr)_minmax(0,11rem)]">
        <div className="space-y-1.5">
          <Label htmlFor="re-kind">{R.kind}</Label>
          <NativeSelect
            id="re-kind"
            value={kind}
            disabled={disabled}
            onChange={(e) => {
              setKind(e.target.value as EntryKind)
              setError('')
            }}
          >
            {ADD_KINDS.map((k) => (
              <option key={k} value={k}>
                {R.kinds[k]}
              </option>
            ))}
          </NativeSelect>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="re-value">{R.entry}</Label>
          <Input
            id="re-value"
            value={needsText ? text : ''}
            disabled={disabled || !needsText}
            onChange={(e) => {
              setText(e.target.value)
              setError('')
            }}
            placeholder={R.placeholders[kind]}
            autoComplete="off"
            spellCheck={false}
            aria-invalid={error ? true : undefined}
            aria-describedby="re-hint"
            className="font-mono"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="re-list">{R.toList}</Label>
          <NativeSelect id="re-list" value={list} disabled={disabled} onChange={(e) => setList(e.target.value as ListName)}>
            {LISTS.map((l) => (
              <option key={l} value={l}>
                {R.lists[l]}
              </option>
            ))}
          </NativeSelect>
        </div>
      </div>
      <p id="re-hint" className="text-xs text-muted-foreground">
        {R.kindHelp[kind]}
        {!sso && ['group', 'app-role', 'oidc'].includes(kind) && <span className="mt-1 block text-amber-700 dark:text-amber-400">{R.notes.no_sso}</span>}
      </p>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" size="sm" disabled={disabled}>
        <Plus /> {R.add}
      </Button>
    </form>
  )
}

export function RolesEditor() {
  const R = t.auth.rolesEditor
  const { meta } = useMeta()
  const admin = !!meta.user?.canAdmin
  const q = useRoles(admin)
  if (!admin) return <EmptyState icon={<ShieldAlert />} title={R.adminOnly} />
  if (q.isPending) return <Skeleton className="h-64 w-full" />
  if (q.isError) return <EmptyState icon={<CircleAlert className="size-8" />} title={t.errors.generic} body={failureText(q.error)} />
  // the editor restarts whenever the lists it was built from change
  return <Editor key={q.data.version} view={q.data} refetch={() => q.refetch()} />
}

function Editor({ view, refetch }: { view: RolesView; refetch: () => Promise<unknown> }) {
  const R = t.auth.rolesEditor
  const qc = useQueryClient()
  const base = useMemo(() => viewDraft(view), [view])
  const baseEntries = useMemo(() => viewEntries(view), [view])
  const [draft, setDraft] = useState<Draft>(base)
  const [preview, setPreview] = useState<{ draft: Draft; data: RolesPreview } | null>(null)
  const [message, setMessage] = useState('')
  const [conflict, setConflict] = useState(false)
  const [failure, setFailure] = useState('')
  const [opened, setOpened] = useState<{ url: string } | null>(null)

  const locked = view.readOnly || !view.loads || !view.explicit
  const changes = draftChanges(base, draft)
  const dirty = !sameDraft(base, draft)
  const fresh = preview !== null && sameDraft(preview.draft, draft)
  const p = fresh ? preview.data : null
  const annotation = p ? p.entries : baseEntries

  const edit = (next: Draft) => {
    setDraft(next)
    setFailure('')
    setOpened(null)
  }

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'conflict') {
      setConflict(true)
      setPreview(null)
      return
    }
    setFailure(failureText(e))
  }
  const previewM = useMutation({
    mutationFn: () => previewRoles(view.version, draft),
    onSuccess: (data) => setPreview({ draft, data }),
    onError,
  })
  const saveM = useMutation({
    mutationFn: () => saveRoles(view.version, draft, message),
    onSuccess: async (r) => {
      setPreview(null)
      setMessage('')
      if (r.pullRequest) {
        // nothing changes until the pull request is merged: the draft stays as the person left it
        // and so the draft goes back to the server's lists: saving again would open a second pull request
        setOpened({ url: r.pullRequestUrl ?? '' })
        setDraft(base)
        toast.success(R.savedPR)
        return
      }
      toast.success(r.changed ? R.saved : R.noChanges)
      await qc.invalidateQueries({ queryKey: rolesKey })
      await qc.invalidateQueries({ queryKey: ['rb', 'users'] })
    },
    onError,
  })
  const busy = previewM.isPending || saveM.isPending
  const canSave = !!p && p.changed && !p.refusal && !locked && !busy

  const reload = async () => {
    setConflict(false)
    setPreview(null)
    await qc.invalidateQueries({ queryKey: rolesKey })
    await refetch()
  }

  return (
    <div className="space-y-5">
      <p className="max-w-3xl text-sm text-muted-foreground">{view.writeMode === 'pr' ? R.introPR : R.intro}</p>

      {!view.loads && (
        <Alert variant="destructive">
          <CircleAlert />
          <AlertTitle>{R.degradedTitle}</AlertTitle>
          <AlertDescription>
            {R.degradedBody}
            {view.problem && <code className="mt-1 block font-mono text-xs break-all">{view.problem}</code>}
          </AlertDescription>
        </Alert>
      )}
      {view.loads && !view.explicit && (
        <Alert>
          <Info />
          <AlertTitle>{R.noBlockTitle}</AlertTitle>
          <AlertDescription>{R.noBlockBody}</AlertDescription>
        </Alert>
      )}
      {view.readOnly && (
        <Alert>
          <Info />
          <AlertDescription>{R.readOnly}</AlertDescription>
        </Alert>
      )}
      {view.authMode === 'none' && (
        <Alert variant="destructive">
          <TriangleAlert />
          <AlertTitle>{R.authNoneTitle}</AlertTitle>
          <AlertDescription>{R.authNoneBody}</AlertDescription>
        </Alert>
      )}
      {view.editors.length > 0 && (
        <Alert>
          <Info />
          <AlertTitle>{R.legacyTitle}</AlertTitle>
          <AlertDescription>
            {R.legacyBody}
            <ul className="mt-1 space-y-0.5">
              {view.editors.map((e) => (
                <li key={e} className="font-mono text-xs break-all">
                  {e}
                </li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}
      {conflict && (
        <Alert variant="destructive">
          <CircleAlert />
          <AlertTitle>{R.conflictTitle}</AlertTitle>
          <AlertDescription>
            {R.conflictBody}
            <div className="mt-2">
              <Button size="sm" variant="outline" onClick={() => void reload()}>
                <RotateCcw /> {R.reload}
              </Button>
            </div>
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        {LISTS.map((list) => {
          const entries = draft[list]
          const ann = annotation[list]
          const newOnes = new Set(changes.filter((c) => c.list === list && c.op === 'add').map((c) => entryKey(c.value)))
          return (
            <section key={list} className="min-w-0 space-y-2 rounded-xl border bg-card p-4 shadow-xs" aria-labelledby={`re-h-${list}`}>
              <div>
                <h3 id={`re-h-${list}`} className="flex items-center gap-2 text-sm font-semibold">
                  {R.lists[list]}
                  <Badge variant="secondary" className="px-1.5">
                    {entries.length}
                  </Badge>
                </h3>
                <p className="text-xs text-muted-foreground">{R.listHelp[list]}</p>
              </div>
              {entries.length === 0 ? (
                <p className="rounded-lg border border-dashed px-3 py-3 text-sm text-muted-foreground">{R.empty}</p>
              ) : (
                <ul className="space-y-1.5">
                  {entries.map((value, i) => {
                    const found = ann.find((e) => e.value === value)
                    const entry: RoleEntry = found ?? { value, kind: '', notes: [] }
                    return (
                      <Chip
                        key={`${value}-${i}`}
                        list={list}
                        entry={entry}
                        isNew={newOnes.has(entryKey(value))}
                        disabled={locked}
                        onRemove={() => edit(removeEntry(draft, list, value))}
                        onMove={(to) => edit(moveEntry(draft, list, to, value))}
                      />
                    )
                  })}
                </ul>
              )}
            </section>
          )
        })}
      </div>

      <AddForm draft={draft} disabled={locked} sso={view.sso} onAdd={(list, value) => edit(addEntry(draft, list, value))} />

      {view.infra && (
        <p className="flex items-start gap-2 text-xs text-muted-foreground">
          <Info className="mt-px size-3.5 shrink-0" /> {R.infraNote}
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t pt-4">
        <Button onClick={() => previewM.mutate()} disabled={!dirty || locked || busy}>
          {previewM.isPending ? R.previewing : R.preview}
        </Button>
        <Button
          variant="outline"
          disabled={!dirty || busy}
          onClick={() => {
            setDraft(base)
            setPreview(null)
            setFailure('')
          }}
        >
          <RotateCcw /> {R.discard}
        </Button>
        <span className="text-xs text-muted-foreground">{dirty ? R.unsaved(changes.length) : R.noChanges}</span>
      </div>

      {failure && (
        <Alert variant="destructive" role="alert">
          <CircleAlert />
          <AlertDescription>{failure}</AlertDescription>
        </Alert>
      )}

      {opened && (
        <Alert>
          <GitPullRequest />
          <AlertTitle>{R.savedPR}</AlertTitle>
          <AlertDescription>
            {R.prNote}
            {opened.url && (
              <div className="mt-2">
                <Button size="sm" variant="outline" render={<a href={opened.url} target="_blank" rel="noreferrer noopener" />}>
                  <ExternalLink /> {R.openPR}
                </Button>
              </div>
            )}
          </AlertDescription>
        </Alert>
      )}

      {p && (
        <section className="min-w-0 space-y-4 rounded-xl border bg-card p-4 shadow-xs" aria-labelledby="re-preview">
          <h3 id="re-preview" className="text-sm font-semibold">
            {R.previewTitle}
          </h3>
          {p.refusal && (
            <Alert variant="destructive">
              <CircleAlert />
              <AlertTitle>{R.refusedTitle}</AlertTitle>
              <AlertDescription>{refusalText(p.refusal.code, p.refusal.message)}</AlertDescription>
            </Alert>
          )}
          {p.you.after && (
            <p className="text-sm" data-testid="you-will-be">
              <span className="font-medium">{R.youWillBe(capText(p.you.after))}</span>
              {p.you.now && capText(p.you.now) !== capText(p.you.after) && <span className="text-muted-foreground"> · {R.youNow(capText(p.you.now))}</span>}
            </p>
          )}
          {p.warnings.length > 0 && (
            <div className="space-y-1">
              <h4 className="text-xs font-semibold text-muted-foreground">{R.warnings}</h4>
              <ul className="space-y-1">
                {p.warnings.map((w, i) => (
                  <li key={i} className="flex items-start gap-1.5 text-sm text-amber-700 dark:text-amber-400">
                    <TriangleAlert className="mt-0.5 size-3.5 shrink-0" />
                    <span className="min-w-0">
                      <code className="font-mono text-xs break-all">{w.entry}</code>
                      {t.common.colon}
                      {noteText(w.note)}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {p.changed ? (
            <div className="space-y-1.5">
              <h4 className="text-xs font-semibold text-muted-foreground">
                {R.diffTitle}
                {t.common.colon}
                <code className="font-mono">{p.file}</code>
              </h4>
              <DiffView diff={p.diff} className="max-h-[24rem]" />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{R.noChanges}</p>
          )}
          {p.changed && !p.refusal && (
            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="re-msg">{R.message}</Label>
                <Input id="re-msg" value={message} onChange={(e) => setMessage(e.target.value)} placeholder={p.subject} maxLength={200} autoComplete="off" />
                <p className="text-xs text-muted-foreground">{p.pullRequest ? R.prMode : R.pushMode}</p>
              </div>
              <Button onClick={() => saveM.mutate()} disabled={!canSave}>
                {saveM.isPending ? R.saving : p.pullRequest ? R.saveAsPR : R.save}
              </Button>
            </div>
          )}
        </section>
      )}
    </div>
  )
}
