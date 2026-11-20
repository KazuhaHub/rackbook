import { useMemo, useState } from 'react'
import { Plus, Trash2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/ui/native-select'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { t } from '@/i18n'
import { ENUM_COLORS, enumColorClass, enumColorLabel } from '@/lib/enumColors'
import { fieldTypes, type FieldDef, type FieldType, type TypeDef } from '@/lib/typedef'
import { useMeta } from '@/providers/meta'
import { TagInput } from './TagInput'

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_-]{0,63}$/

export type FieldFlags = { list: boolean; facet: boolean }

function Row({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

const num = (v: string): number | undefined => {
  if (v.trim() === '') return undefined
  const n = Number(v)
  return Number.isFinite(n) ? n : undefined
}

/** Options that belong to a type; switching type drops the others. */
function reshape(f: FieldDef, type: FieldType, draft: TypeDef): FieldDef {
  const base: FieldDef = {
    name: f.name,
    title: f.title,
    description: f.description,
    type,
    required: f.required,
    unique: f.unique,
    advanced: f.advanced,
    extras: f.extras,
  }
  if (type === 'enum') base.enum = f.enum?.length ? f.enum : [{ value: '' }]
  if (type === 'ref') {
    base.ref = f.ref ?? { to: '', toField: '' }
    base.unique = f.unique
  } else if (type === 'bool') {
    base.default = typeof f.default === 'boolean' ? f.default : undefined
  } else if (['text', 'textarea', 'integer', 'number', 'ip', 'ipv4', 'ipv6', 'cidr', 'hostname', 'url', 'date', 'port', 'port-spec'].includes(type)) {
    base.default = f.default
  }
  void draft
  return base
}

export function FieldDialog({
  open,
  onOpenChange,
  initial,
  locked,
  draft,
  flags,
  onSave,
  presetType,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  /** the field being edited; null adds a new one */
  initial: FieldDef | null
  /** the field already exists in the saved type: its name cannot change */
  locked: boolean
  draft: TypeDef
  flags: FieldFlags
  onSave: (f: FieldDef, flags: FieldFlags) => void
  presetType?: FieldType
}) {
  // The parent re-keys this component for every field it opens, so state starts from props.
  const { meta } = useMeta()
  const [f, setF] = useState<FieldDef>(() => initial ?? reshape({ name: '', type: 'text', required: false, unique: false }, presetType ?? 'text', draft))
  const [fl, setFl] = useState<FieldFlags>(flags)
  const set = (patch: Partial<FieldDef>) => setF((x) => ({ ...x, ...patch }))
  const advanced = f.type === 'advanced'

  const taken = draft.fields.some((x) => x.name === f.name && x.name !== initial?.name)
  const nameErr = !locked && f.name !== '' && !NAME_RE.test(f.name) ? t.types.dialog.nameBad : taken ? t.types.dialog.nameTaken : ''

  const targets = useMemo(() => {
    const out = meta.collections.filter((c) => c.name !== draft.name).map((c) => ({ name: c.name, title: c.title, fields: Object.keys(c.schema.properties ?? {}), key: c.key ?? [] }))
    if (draft.name) out.unshift({ name: draft.name, title: draft.title || draft.name, fields: draft.fields.map((x) => x.name).filter(Boolean), key: draft.key })
    return out
  }, [meta.collections, draft])

  const target = f.ref ? targets.find((x) => x.name === f.ref!.to) : undefined

  let problem = ''
  if (!f.name) problem = t.types.dialog.name
  else if (nameErr) problem = nameErr
  else if (f.type === 'enum' && (!f.enum?.length || f.enum.some((e) => !e.value) || new Set(f.enum.map((e) => e.value)).size !== f.enum.length)) problem = t.types.dialog.enumEmpty
  else if (f.type === 'ref' && (!f.ref?.to || !f.ref.toField)) problem = t.types.dialog.refTarget

  const setRef = (patch: Partial<NonNullable<FieldDef['ref']>>) => set({ ref: { ...(f.ref ?? { to: '', toField: '' }), ...patch } })

  const pickTarget = (name: string) => {
    const tg = targets.find((x) => x.name === name)
    setRef({ to: name, toField: tg?.key[0] ?? tg?.fields[0] ?? '' })
  }

  const defaultInput = () => {
    if (f.type === 'bool')
      return (
        <NativeSelect value={f.default === undefined ? '' : String(f.default)} onChange={(e) => set({ default: e.target.value === '' ? undefined : e.target.value === 'true' })}>
          <option value="">{t.types.dialog.noDefault}</option>
          <option value="true">{t.types.dialog.boolTrue}</option>
          <option value="false">{t.types.dialog.boolFalse}</option>
        </NativeSelect>
      )
    if (f.type === 'enum')
      return (
        <NativeSelect value={f.default === undefined ? '' : String(f.default)} onChange={(e) => set({ default: e.target.value === '' ? undefined : e.target.value })}>
          <option value="">{t.types.dialog.noDefault}</option>
          {(f.enum ?? []).filter((x) => x.value).map((x) => (
            <option key={x.value} value={x.value}>
              {x.value}
            </option>
          ))}
        </NativeSelect>
      )
    const numeric = f.type === 'integer' || f.type === 'number' || f.type === 'port'
    return (
      <Input
        value={f.default === undefined ? '' : String(f.default)}
        inputMode={numeric ? 'decimal' : undefined}
        onChange={(e) => set({ default: e.target.value === '' ? undefined : numeric ? (num(e.target.value) ?? f.default) : e.target.value })}
      />
    )
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{initial ? t.types.dialog.editTitle(initial.name) : t.types.dialog.addTitle}</DialogTitle>
        </DialogHeader>

        <div className="grid gap-4 sm:grid-cols-2">
          <Row label={t.types.dialog.name} hint={locked ? t.types.dialog.nameFixed : t.types.dialog.nameHint}>
            <Input value={f.name} disabled={locked} aria-invalid={!!nameErr} className="font-mono" onChange={(e) => set({ name: e.target.value })} />
            {nameErr && <p className="text-xs text-destructive">{nameErr}</p>}
          </Row>
          <Row label={t.types.dialog.title}>
            <Input value={f.title ?? ''} onChange={(e) => set({ title: e.target.value })} />
          </Row>
          <Row label={t.types.dialog.type} hint={fieldTypes().find((x) => x.type === f.type)?.hint}>
            {advanced ? (
              <div className="flex h-8 items-center">
                <Badge variant="outline">{t.types.fields.advanced}</Badge>
              </div>
            ) : (
              <NativeSelect value={f.type} onChange={(e) => setF(reshape(f, e.target.value as FieldType, draft))}>
                {fieldTypes().map((x) => (
                  <option key={x.type} value={x.type}>
                    {x.label}
                  </option>
                ))}
              </NativeSelect>
            )}
            {locked && !advanced && <p className="text-xs text-muted-foreground">{t.types.dialog.typeChangeHint}</p>}
          </Row>
          <Row label={t.types.dialog.description}>
            <Input value={f.description ?? ''} onChange={(e) => set({ description: e.target.value })} />
          </Row>
        </div>

        {(f.advanced || advanced) && (
          <div className="rounded-lg border border-dashed bg-muted/30 p-3 text-xs text-muted-foreground">
            <p className="font-medium text-foreground">{t.types.fields.advanced}</p>
            <p className="mt-1">{t.types.fields.advancedHint}</p>
            {f.extras && f.extras.length > 0 && (
              <>
                <p className="mt-2">{t.types.fields.extras}</p>
                <pre className="mt-1 overflow-x-auto font-mono leading-relaxed">{f.extras.map((e) => `${e.key}: ${JSON.stringify(e.value)}`).join('\n')}</pre>
              </>
            )}
          </div>
        )}

        {/* options of the type */}
        {f.type === 'text' && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Row label={t.types.dialog.minLength}>
              <Input inputMode="numeric" value={f.minLength ?? ''} onChange={(e) => set({ minLength: num(e.target.value) })} />
            </Row>
            <Row label={t.types.dialog.maxLength}>
              <Input inputMode="numeric" value={f.maxLength ?? ''} onChange={(e) => set({ maxLength: num(e.target.value) })} />
            </Row>
            <div className="sm:col-span-2">
              <Row label={t.types.dialog.pattern} hint={t.types.dialog.patternHint}>
                <Input className="font-mono" value={f.pattern ?? ''} onChange={(e) => set({ pattern: e.target.value || undefined })} />
              </Row>
            </div>
            <div className="sm:col-span-2">
              <Row label={t.types.dialog.examples} hint={t.types.dialog.examplesHint}>
                <TagInput value={f.examples ?? []} onChange={(v) => set({ examples: v.length ? v : undefined })} />
              </Row>
            </div>
          </div>
        )}
        {(f.type === 'integer' || f.type === 'number') && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Row label={t.types.dialog.min}>
              <Input inputMode="decimal" value={f.min ?? ''} onChange={(e) => set({ min: num(e.target.value) })} />
            </Row>
            <Row label={t.types.dialog.max}>
              <Input inputMode="decimal" value={f.max ?? ''} onChange={(e) => set({ max: num(e.target.value) })} />
            </Row>
          </div>
        )}
        {f.type === 'enum' && (
          <Row label={t.types.dialog.enumValues}>
            <div className="space-y-2">
              {(f.enum ?? []).map((it, i) => (
                <div key={i} className="flex items-center gap-2">
                  <Input
                    value={it.value}
                    placeholder={t.types.dialog.enumValue}
                    onChange={(e) => set({ enum: f.enum!.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)) })}
                  />
                  <NativeSelect
                    className={`w-32 ${it.color ? enumColorClass[it.color] : ''}`}
                    value={it.color ?? ''}
                    aria-label={t.types.dialog.enumColor}
                    onChange={(e) => set({ enum: f.enum!.map((x, j) => (j === i ? { ...x, color: e.target.value || undefined } : x)) })}
                  >
                    <option value="">{t.types.dialog.colors.none}</option>
                    {ENUM_COLORS.map((c) => (
                      <option key={c} value={c}>
                        {enumColorLabel(c)}
                      </option>
                    ))}
                  </NativeSelect>
                  <Button type="button" variant="ghost" size="icon-sm" aria-label={t.types.fields.remove} onClick={() => set({ enum: f.enum!.filter((_, j) => j !== i) })}>
                    <Trash2 />
                  </Button>
                </div>
              ))}
              <Button type="button" variant="outline" size="sm" onClick={() => set({ enum: [...(f.enum ?? []), { value: '' }] })}>
                <Plus /> {t.types.dialog.enumAdd}
              </Button>
            </div>
          </Row>
        )}
        {f.type === 'ref' && (
          <div className="grid gap-4 sm:grid-cols-2">
            <Row label={t.types.dialog.refTarget}>
              <NativeSelect value={f.ref?.to ?? ''} onChange={(e) => pickTarget(e.target.value)}>
                <option value="" disabled>
                  —
                </option>
                {targets.map((x) => (
                  <option key={x.name} value={x.name}>
                    {x.title}
                    {t.common.paren(x.name)}
                  </option>
                ))}
              </NativeSelect>
            </Row>
            <Row label={t.types.dialog.refField} hint={t.types.dialog.refFieldHint}>
              <NativeSelect value={f.ref?.toField ?? ''} disabled={!target} onChange={(e) => setRef({ toField: e.target.value })}>
                {(target?.fields ?? []).map((x) => (
                  <option key={x} value={x}>
                    {x}
                  </option>
                ))}
              </NativeSelect>
            </Row>
            <div className="sm:col-span-2">
              <Row label={t.types.dialog.refAllow} hint={t.types.dialog.refAllowHint}>
                <TagInput mono value={f.ref?.allow ?? []} onChange={(v) => setRef({ allow: v.length ? v : undefined })} />
              </Row>
            </div>
            <div className="flex items-center gap-2 sm:col-span-2">
              <Switch id="ref-many" checked={!!f.ref?.many} onCheckedChange={(v) => setRef({ many: v || undefined })} />
              <Label htmlFor="ref-many">{t.types.dialog.refMany}</Label>
            </div>
            <Row label={t.types.dialog.refBackTitle} hint={t.types.dialog.refBackTitleHint}>
              <Input value={f.ref?.backrefTitle ?? ''} onChange={(e) => setRef({ backrefTitle: e.target.value || undefined })} />
            </Row>
            <Row label={t.types.dialog.refBackColumns} hint={t.types.dialog.refBackColumnsHint}>
              <TagInput mono value={f.ref?.backrefColumns ?? []} onChange={(v) => setRef({ backrefColumns: v.length ? v : undefined })} />
            </Row>
            <div className="sm:col-span-2">
              <Row label={t.types.dialog.refMessage}>
                <Input value={f.ref?.message ?? ''} onChange={(e) => setRef({ message: e.target.value || undefined })} />
              </Row>
            </div>
          </div>
        )}

        {!advanced && f.type !== 'ref' && f.type !== 'textarea' && (
          <Row label={t.types.dialog.defaultValue} hint={t.types.dialog.defaultHint}>
            {defaultInput()}
          </Row>
        )}
        {f.type === 'textarea' && (
          <Row label={t.types.dialog.defaultValue} hint={t.types.dialog.defaultHint}>
            <Textarea rows={2} value={f.default === undefined ? '' : String(f.default)} onChange={(e) => set({ default: e.target.value || undefined })} />
          </Row>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          {(
            [
              ['required', t.types.dialog.required, f.required, (v: boolean) => set({ required: v })],
              ['unique', t.types.dialog.unique, f.unique, (v: boolean) => set({ unique: v })],
              ['list', t.types.dialog.list, fl.list, (v: boolean) => setFl({ ...fl, list: v })],
              ['facet', t.types.dialog.facet, fl.facet, (v: boolean) => setFl({ ...fl, facet: v })],
            ] as const
          ).map(([id, label, value, change]) => (
            <label key={id} className="flex items-center gap-2 text-sm">
              <Checkbox checked={value} onCheckedChange={(v) => change(!!v)} />
              {label}
            </label>
          ))}
        </div>

        <DialogFooter>
          <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
            {t.types.dialog.cancel}
          </Button>
          <Button
            type="button"
            disabled={!!problem}
            title={problem}
            onClick={() => {
              onSave(f, fl)
              onOpenChange(false)
            }}
          >
            {t.types.dialog.save}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
