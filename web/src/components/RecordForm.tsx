import { useMemo } from 'react'
import Form from '@rjsf/shadcn'
import { customizeValidator } from '@rjsf/validator-ajv8'
import type { ErrorSchema, RJSFSchema, RJSFValidationError, UiSchema } from '@rjsf/utils'
import { Ajv2020 } from 'ajv/dist/2020.js'
import { t } from '@/i18n/zh-CN'
import { useAllRecords } from '@/lib/hooks'
import { pointerToPath, str } from '@/lib/ledger'
import type { CheckError, Collection } from '@/lib/types'
import { RefWidget, SwitchWidget, type RefItem } from './form-widgets'

// Draft 2020-12, the same dialect the server validates with.
const validator = customizeValidator({
  AjvClass: Ajv2020 as any,
  customFormats: { textarea: () => true },
})

const widgets = { RefWidget, SwitchWidget }

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
      case 'additionalProperties':
        message = `不允许的字段：${p.additionalProperty}`
        break
    }
    return { ...e, message }
  })
}

function useRefItems(col: Collection) {
  const refs = useMemo(() => (col.refs ?? []).filter((r) => !r.many), [col])
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

  const { schema, uiSchema } = useMemo(() => {
    const s = structuredClone(col.schema) as RJSFSchema
    // the page header already carries the collection title; the root object needs no heading
    delete s.title
    delete s.description
    delete s.$schema
    const ui: UiSchema = { 'ui:submitButtonOptions': { norender: true } }
    for (const [field, prop] of Object.entries(s.properties ?? {}) as [string, any][]) {
      if (prop.format === 'textarea') {
        delete prop.format
        ui[field] = { 'ui:widget': 'textarea', 'ui:options': { rows: 4 } }
      } else if (prop.type === 'boolean') {
        ui[field] = { 'ui:widget': 'SwitchWidget' }
      } else if (refItems[field]) {
        ui[field] = { 'ui:widget': 'RefWidget', 'ui:options': { items: refItems[field] } }
      }
    }
    return { schema: s, uiSchema: ui }
  }, [col, refItems])

  const extraErrors = useMemo(() => toErrorSchema(serverErrors, schema, col.name), [serverErrors, schema, col.name])

  return (
    <Form
      id={formId}
      schema={schema}
      uiSchema={uiSchema}
      formData={formData}
      validator={validator}
      widgets={widgets}
      disabled={disabled}
      noHtml5Validate
      showErrorList={false}
      transformErrors={transformErrors}
      extraErrors={extraErrors}
      experimental_defaultFormStateBehavior={{ emptyObjectFields: 'populateRequiredDefaults' }}
      onChange={(e) => onChange((e.formData ?? {}) as Record<string, unknown>)}
      onSubmit={(e) => onSubmit((e.formData ?? {}) as Record<string, unknown>)}
      onError={(errs) => { onInvalid?.(errs.map((e) => (e.property && e.property !== '.' ? `${e.property.replace(/^\./, '')}：` : '') + (e.message ?? e.stack ?? '')))}}
    />
  )
}
