import { useMemo, useState } from 'react'
import Form, { generateTemplates } from '@rjsf/shadcn'
import { customizeValidator } from '@rjsf/validator-ajv8'
import type { ErrorSchema, FieldTemplateProps, RJSFSchema, RJSFValidationError, UiSchema } from '@rjsf/utils'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { t } from '@/i18n/zh-CN'
import { useAllRecords } from '@/lib/hooks'
import { fieldKind, suggestValues, type Prop } from '@/lib/fieldKind'
import { pointerToPath, str } from '@/lib/ledger'
import type { CheckError, Collection } from '@/lib/types'
import { customFormats, formatHints } from '@/lib/formats'
import { DateWidget, EnumWidget, ListWidget, RefManyWidget, RefWidget, SuggestWidget, SwitchWidget, TagsWidget, type RefItem } from './form-widgets'

// Draft 2020-12, the same dialect the server validates with.
const validator = customizeValidator({
  AjvClass: Ajv2020 as any,
  customFormats,
})

const widgets = { RefWidget, RefManyWidget, SwitchWidget, EnumWidget, TagsWidget, SuggestWidget, DateWidget, ListWidget }

// A field shows its errors once the user has been in it (or tried to save), not while it is untouched.
// formContext carries plain data (not a function) so the fields re-render when it changes.
type FormCtx = { touched: string[]; all: boolean }
const BaseFieldTemplate = generateTemplates().FieldTemplate!
function FieldTemplate(props: FieldTemplateProps) {
  const ctx = props.registry.formContext as FormCtx
  const show = ctx.all || ctx.touched.some((x) => x === props.id || x.startsWith(props.id + '_'))
  return <BaseFieldTemplate {...props} rawErrors={show ? props.rawErrors : []} errors={(show ? props.errors : null) as FieldTemplateProps['errors']} />
}
const templates = { FieldTemplate }

/** Server errors (JSON pointers) -> rjsf ErrorSchema so they show under the matching field. */
export function toErrorSchema(errors: CheckError[], schema: RJSFSchema, collection: string): ErrorSchema {
  const root: any = {}
  for (const e of errors) {
    // errors about other collections (e.g. a rename that breaks references) only go to the summary
    if (e.collection && e.collection !== collection) continue
    const path = pointerToPath(e.path)
    if (!path.length || !schema.properties?.[path[0]]) continue
    let node = root
    for (const seg of path) node = node[seg] ??= {}
    ;(node.__errors ??= []).push(e.message)
  }
  return root
}

function transformErrors(errors: RJSFValidationError[]): RJSFValidationError[] {
  return errors.map((e) => {
    const p = e.params ?? {}
    let message = e.message
    switch (e.name) {
      case 'required':
        message = t.form.required
        break
      case 'pattern':
        message = `格式不正确（需匹配 ${p.pattern}）`
        break
      case 'type':
        message = `类型应为 ${p.type}`
        break
      case 'enum':
        message = `只能是：${(p.allowedValues ?? []).join('、')}`
        break
      case 'minLength':
        message = `至少 ${p.limit} 个字符`
        break
      case 'maxLength':
        message = `最多 ${p.limit} 个字符`
        break
      case 'minimum':
      case 'maximum':
        message = `超出范围（${e.name === 'minimum' ? '≥' : '≤'} ${p.limit}）`
        break
      case 'format':
        message = formatHints[String(p.format)] ?? `格式不正确（${p.format}）`
        break
      case 'additionalProperties':
        message = `不允许的字段：${p.additionalProperty}`
        break
    }
    return { ...e, message }
  })
}

function useRefItems(col: Collection) {
  const refs = useMemo(() => col.refs ?? [], [col])
  const results = useAllRecords(
    refs.map((r) => r.to),
    true,
  )
  const stamp = results.map((r) => r.dataUpdatedAt).join(',')
  return useMemo(() => {
    const out: Record<string, RefItem[]> = {}
    refs.forEach((r, i) => {
      const items: RefItem[] = (results[i]?.data ?? [])
        .map((rec) => str(rec.data[r.toField]))
        .filter(Boolean)
        .map((v) => ({ value: v, label: v }))
      for (const lit of r.allow ?? []) if (!items.some((x) => x.value === lit)) items.push({ value: lit, label: lit, literal: true })
      out[r.field] = items
    })
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refs, stamp])
}

export function RecordForm({
  col,
  formId,
  formData,
  onChange,
  onSubmit,
  serverErrors,
  disabled,
  onInvalid,
}: {
  col: Collection
  formId: string
  formData: Record<string, unknown>
  onChange: (d: Record<string, unknown>) => void
  onSubmit: (d: Record<string, unknown>) => void
  serverErrors: CheckError[]
  disabled?: boolean
  onInvalid?: (messages: string[]) => void
}) {
  const refItems = useRefItems(col)
  const own = useAllRecords([col.name], true)[0]
  const ownRecords = own?.data
  const [touched, setTouched] = useState<string[]>([])
  const [tried, setTried] = useState(false)
  const touch = (id: string) => id && setTouched((x) => (x.includes(id) ? x : [...x, id]))

  const { schema, uiSchema } = useMemo(() => {
    const s = structuredClone(col.schema) as RJSFSchema
    // the page header already carries the collection title; the root object needs no heading
    delete s.title
    delete s.description
    delete s.$schema
    const ui: UiSchema = { 'ui:submitButtonOptions': { norender: true } }
    for (const [field, prop] of Object.entries(s.properties ?? {}) as [string, any][]) {
      if (refItems[field]) {
        ui[field] = { 'ui:widget': prop.type === 'array' ? 'RefManyWidget' : 'RefWidget', 'ui:options': { items: refItems[field] } }
        continue
      }
      switch (fieldKind(prop as Prop, { isKey: !!col.key?.includes(field), isRef: false })) {
        case 'textarea':
          delete prop.format
          ui[field] = { 'ui:widget': 'textarea', 'ui:options': { rows: 4 } }
          break
        case 'boolean':
          ui[field] = { 'ui:widget': 'SwitchWidget' }
          break
        case 'enum':
          ui[field] = { 'ui:widget': 'EnumWidget' }
          break
        case 'tags':
          ui[field] = { 'ui:widget': 'TagsWidget' }
          break
        case 'list':
          ui[field] = { 'ui:widget': 'ListWidget' }
          break
        case 'date':
          ui[field] = { 'ui:widget': 'DateWidget' }
          break
        case 'suggest':
          ui[field] = { 'ui:widget': 'SuggestWidget', 'ui:options': { suggestions: suggestValues(ownRecords ?? [], field) } }
          break
      }
    }
    return { schema: s, uiSchema: ui }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [col, refItems, own?.dataUpdatedAt])

  const extraErrors = useMemo(() => toErrorSchema(serverErrors, schema, col.name), [serverErrors, schema, col.name])

  return (
    <div onBlur={(e) => touch((e.target as HTMLElement).id)}>
    <Form
      id={formId}
      schema={schema}
      uiSchema={uiSchema}
      formData={formData}
      validator={validator}
      widgets={widgets}
      templates={templates}
      formContext={{ touched, all: tried || serverErrors.length > 0 } satisfies FormCtx}
      liveValidate
      disabled={disabled}
      noHtml5Validate
      showErrorList={false}
      transformErrors={transformErrors}
      extraErrors={extraErrors}
      experimental_defaultFormStateBehavior={{ emptyObjectFields: 'populateRequiredDefaults' }}
      onChange={(e, id) => {
        touch(id ?? '')
        onChange((e.formData ?? {}) as Record<string, unknown>)
      }}
      onSubmit={(e) => {
        setTried(true)
        onSubmit((e.formData ?? {}) as Record<string, unknown>)
      }}
      onError={(errs) => { setTried(true); onInvalid?.(errs.map((e) => (e.property && e.property !== '.' ? `${e.property.replace(/^\./, '')}：` : '') + (e.message ?? e.stack ?? '')))}}
    />
    </div>
  )
}
