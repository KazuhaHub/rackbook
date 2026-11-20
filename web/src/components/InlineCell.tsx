import { useState } from 'react'
import { ChevronDown, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command'
import { Input } from '@/components/ui/input'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { t } from '@/i18n'
import { type InlineKind, type Prop } from '@/lib/fieldKind'
import { enumNames, enumOptions, type EnumOption } from '@/lib/labels'
import { isDate } from '@/lib/formats'
import { cn } from '@/lib/utils'
import { BoolBadge, CellValue } from './CellValue'
import { EnumIcon } from './EnumIcon'

const trigger =
  'group/inline -mx-1.5 inline-flex max-w-full items-center gap-1 rounded-md px-1.5 py-0.5 text-left outline-none hover:bg-foreground/5 focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-wait disabled:opacity-60'

function Chevron({ busy }: { busy: boolean }) {
  return busy ? (
    <Loader2 className="size-3 shrink-0 animate-spin text-muted-foreground" />
  ) : (
    <ChevronDown className="size-3 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover/inline:opacity-70 group-focus-visible/inline:opacity-70" />
  )
}

/**
 * A list cell that edits in place: a toggle for booleans, a picker for enums
 * and for arrays of enum values, a date input for dates. `onSave` gets the new
 * value (undefined clears the field); the caller writes it and reverts on failure.
 */
export function InlineCell({
  kind,
  prop,
  value,
  label,
  required,
  busy,
  version,
  onSave,
}: {
  kind: InlineKind
  prop: Prop
  value: unknown
  label: string
  required: boolean
  busy: boolean
  /** the record's hash: a draft made against another version is dropped */
  version: string
  onSave: (v: unknown) => void
}) {
  const aria = t.inline.edit(label)
  if (kind === 'boolean') {
    return (
      <button type="button" className={trigger} disabled={busy} aria-label={aria} aria-pressed={value === true} onClick={() => onSave(value !== true)}>
        <BoolBadge value={value === true} />
        <Chevron busy={busy} />
      </button>
    )
  }
  if (kind === 'date') return <DateCell value={value} label={label} aria={aria} required={required} busy={busy} onSave={onSave} />
  return (
    <PickCell
      multiple={kind === 'tags'}
      prop={prop}
      options={enumOptions(prop)}
      value={value}
      aria={aria}
      required={required}
      busy={busy}
      version={version}
      onSave={onSave}
    />
  )
}

function PickCell({
  multiple,
  prop,
  options,
  value,
  aria,
  required,
  busy,
  version,
  onSave,
}: {
  multiple: boolean
  prop: Prop
  options: EnumOption[]
  value: unknown
  aria: string
  required: boolean
  busy: boolean
  version: string
  onSave: (v: unknown) => void
}) {
  const current = multiple ? (Array.isArray(value) ? value.map(String) : []) : typeof value === 'string' ? value : undefined
  const [open, setOpen] = useState(false)
  // the tag draft belongs to the record version it was started from; another version resets it
  const [draftState, setDraftState] = useState<{ version: string; values: string[] }>({ version, values: [] })
  const draft = draftState.version === version ? draftState.values : multiple ? (current as string[]) : []
  const setDraft = (f: (d: string[]) => string[]) => setDraftState({ version, values: f(draft) })
  // a value the schema no longer lists stays selectable, so it can be seen and removed
  const stored = multiple ? (current as string[]) : current ? [current as string] : []
  const all: EnumOption[] = [...options, ...stored.filter((v) => !options.some((o) => o.value === v)).map((v) => ({ value: v, label: v }))]
  const changed = multiple && !(draft.length === (current as string[]).length && draft.every((v) => (current as string[]).includes(v)))

  // closing without 确定 (Escape, a click outside) discards the draft
  const onOpenChange = (o: boolean) => {
    if (o) setDraftState({ version, values: multiple ? (current as string[]) : [] })
    setOpen(o)
  }
  const confirm = () => {
    setOpen(false)
    if (changed) onSave(all.map((o) => o.value).filter((v) => draft.includes(v)))
  }
  const choose = (v: string) => {
    if (multiple) setDraft((d) => (d.includes(v) ? d.filter((x) => x !== v) : [...d, v]))
    else {
      setOpen(false)
      if (v !== current) onSave(v)
    }
  }
  const checked = (v: string) => (multiple ? draft.includes(v) : v === current)

  return (
    <Popover open={open} onOpenChange={onOpenChange}>
      <PopoverTrigger render={<button type="button" className={trigger} disabled={busy} aria-label={aria} />}>
        <CellValue value={value} schema={prop} />
        <Chevron busy={busy} />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-56 gap-0 p-0">
        <Command>
          {all.length > 6 && <CommandInput placeholder={t.inline.search} />}
          <CommandList>
            <CommandEmpty>{t.form.noReferenceMatch}</CommandEmpty>
            <CommandGroup>
              {all.map((o) => (
                <CommandItem key={o.value} value={o.value} keywords={enumNames(prop, o.value)} data-checked={checked(o.value)} onSelect={() => choose(o.value)}>
                  <EnumIcon name={o.icon} />
                  {o.label}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
          {!required && !multiple && current !== undefined && (
            <div className="border-t p-1">
              <Button
                variant="ghost"
                size="sm"
                className="w-full justify-start text-muted-foreground"
                onClick={() => {
                  setOpen(false)
                  onSave(undefined)
                }}
              >
                {t.inline.clear}
              </Button>
            </div>
          )}
          {multiple && (
            <div className="flex justify-end gap-2 border-t p-1.5">
              <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
                {t.inline.cancel}
              </Button>
              <Button size="sm" disabled={!changed} onClick={confirm}>
                {t.inline.confirm}
              </Button>
            </div>
          )}
        </Command>
      </PopoverContent>
    </Popover>
  )
}

function DateCell({
  value,
  label,
  aria,
  required,
  busy,
  onSave,
}: {
  value: unknown
  label: string
  aria: string
  required: boolean
  busy: boolean
  onSave: (v: unknown) => void
}) {
  const current = typeof value === 'string' ? value : ''
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState(current)
  const valid = isDate(draft)
  const done = (v: unknown) => {
    setOpen(false)
    onSave(v)
  }
  return (
    <Popover
      open={open}
      onOpenChange={(o) => {
        if (o) setDraft(current)
        setOpen(o)
      }}
    >
      <PopoverTrigger render={<button type="button" className={trigger} disabled={busy} aria-label={aria} />}>
        <CellValue value={value} />
        <Chevron busy={busy} />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-56">
        <label className="text-xs text-muted-foreground" htmlFor="inline-date">
          {label}
        </label>
        <Input
          id="inline-date"
          type="date"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && valid && draft !== current) done(draft)
          }}
          aria-invalid={draft !== '' && !valid ? true : undefined}
        />
        <div className={cn('flex gap-2', required ? 'justify-end' : 'justify-between')}>
          {!required && (
            <Button variant="ghost" size="sm" disabled={current === ''} onClick={() => done(undefined)}>
              {t.inline.clear}
            </Button>
          )}
          <Button size="sm" disabled={!valid || draft === current} onClick={() => done(draft)}>
            {t.inline.save}
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  )
}
