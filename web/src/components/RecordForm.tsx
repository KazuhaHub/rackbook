import { useCallback, useMemo, useRef, useState } from 'react'
import Form, { generateTemplates } from '@rjsf/shadcn'
import { customizeValidator } from '@rjsf/validator-ajv8'
import { TranslatableString, type ErrorSchema, type FieldTemplateProps, type RJSFSchema, type RJSFValidationError, type UiSchema } from '@rjsf/utils'
import { Ajv2020 } from 'ajv/dist/2020.js'
import localizeEn from 'ajv-i18n/localize/en'
import localizeZh from 'ajv-i18n/localize/zh'
import localizeZhTW from 'ajv-i18n/localize/zh-TW'
import { locale, t, type Messages } from '@/i18n'
import { useAllRecords } from '@/lib/hooks'
import { enumForm, fieldKind, suggestValues, type Prop } from '@/lib/fieldKind'
import { enumChoices, fieldDescription, fieldTitle, propAt } from '@/lib/labels'
import { pointerToPath, str } from '@/lib/ledger'
import type { CheckError, Collection } from '@/lib/types'
import { issueText } from '@/lib/issues'
import { customFormats, formatHint } from '@/lib/formats'
import { CountryWidget, DateWidget, EnumWidget, ListWidget, RefManyWidget, RowsWidget, RefWidget, SuggestWidget, SwitchWidget, TagsWidget, type RefItem } from './form-widgets'

// Draft 2020-12, the same dialect the server validates with.
// Ajv's own messages are translated by ajv-i18n for the keywords transformErrors
// does not rewrite; the language is chosen when a validation runs, not at load.
const localizers = { 'zh-CN': localizeZh, 'zh-TW': localizeZhTW, 'en-US': localizeEn }
const validator = customizeValidator(
  {
    AjvClass: Ajv2020 as any,
    customFormats,
  },
  (errors) => localizers[locale](errors),
)

const widgets = { CountryWidget, RefWidget, RefManyWidget, SwitchWidget, EnumWidget, TagsWidget, SuggestWidget, DateWidget, ListWidget, RowsWidget }

// A field shows its errors once the user has been in it (or tried to save), not while it is untouched.
// formContext carries plain data (not a function) so the fields re-render when it changes.
// `setPending(field, text)` is how a list field reports the text left in its input box.
type FormCtx = { touched: string[]; all: boolean; setPending: (field: string, text: string) => void }
const BaseFieldTemplate = generateTemplates().FieldTemplate!
function FieldTemplate(props: FieldTemplateProps) {
  const ctx = props.registry.formContext as FormCtx
  const show = ctx.all || ctx.touched.includes(props.id)
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
    ;(node.__errors ??= []).push(issueText(e, [{ name: collection, schema: schema as Prop }]))
  }
  return root
}

function transformErrors(errors: RJSFValidationError[], root: Prop): RJSFValidationError[] {
  const v = t.validation
  return errors.map((e) => {
    const p = e.params ?? {}
    let message = e.message
    switch (e.name) {
      case 'required':
        message = t.form.required
        break
      case 'pattern':
        message = v.pattern(String(p.pattern))
        break
      case 'type':
        message = v.type(String(p.type))
        break
      case 'enum':
        // the allowed codes with their labels in the current language
        message = v.enum(enumChoices(propAt(root, e.property ?? ''), (p.allowedValues ?? []).map(String)))
        break
      case 'minLength':
        message = v.minLength(Number(p.limit))
        break
      case 'maxLength':
        message = v.maxLength(Number(p.limit))
        break
      case 'minimum':
        message = v.minimum(p.limit)
        break
      case 'maximum':
        message = v.maximum(p.limit)
        break
      case 'format':
        message = formatHint(String(p.format)) ?? v.formatFallback(String(p.format))
        break
      case 'additionalProperties':
        message = v.additionalProperty(String(p.additionalProperty))
        break
    }
    return { ...e, message }
  })
}

/** TranslatableString -> its message in t.rjsf; the Record type makes the compiler check every member is covered. */
const rjsfKeys: Record<TranslatableString, keyof Messages['rjsf']> = {
  [TranslatableString.ArrayItemTitle]: 'arrayItemTitle',
  [TranslatableString.MissingItems]: 'missingItems',
  [TranslatableString.EmptyArray]: 'emptyArray',
  [TranslatableString.YesLabel]: 'yesLabel',
  [TranslatableString.NoLabel]: 'noLabel',
  [TranslatableString.CloseLabel]: 'closeLabel',
  [TranslatableString.ErrorsLabel]: 'errorsLabel',
  [TranslatableString.NewStringDefault]: 'newStringDefault',
  [TranslatableString.AddButton]: 'addButton',
  [TranslatableString.AddItemButton]: 'addItemButton',
  [TranslatableString.CopyButton]: 'copyButton',
  [TranslatableString.ExpandButton]: 'expandButton',
  [TranslatableString.MoveDownButton]: 'moveDownButton',
  [TranslatableString.MoveUpButton]: 'moveUpButton',
  [TranslatableString.RemoveButton]: 'removeButton',
  [TranslatableString.NowLabel]: 'nowLabel',
  [TranslatableString.ClearLabel]: 'clearLabel',
  [TranslatableString.AriaDateLabel]: 'ariaDateLabel',
  [TranslatableString.PreviewLabel]: 'previewLabel',
  [TranslatableString.DecrementAriaLabel]: 'decrementAriaLabel',
  [TranslatableString.IncrementAriaLabel]: 'incrementAriaLabel',
  [TranslatableString.OptionalObjectAdd]: 'optionalObjectAdd',
  [TranslatableString.OptionalObjectRemove]: 'optionalObjectRemove',
  [TranslatableString.OptionalObjectEmptyMsg]: 'optionalObjectEmptyMsg',
  [TranslatableString.Type]: 'type',
  [TranslatableString.Value]: 'value',
  [TranslatableString.ClearButton]: 'clearButton',
  [TranslatableString.UnknownFieldType]: 'unknownFieldType',
  [TranslatableString.OptionPrefix]: 'optionPrefix',
  [TranslatableString.TitleOptionPrefix]: 'titleOptionPrefix',
  [TranslatableString.KeyLabel]: 'keyLabel',
  [TranslatableString.DeprecatedLabel]: 'deprecatedLabel',
  [TranslatableString.CycleDetected]: 'cycleDetected',
  [TranslatableString.InvalidObjectField]: 'invalidObjectField',
  [TranslatableString.UnsupportedField]: 'unsupportedField',
  [TranslatableString.UnsupportedFieldWithId]: 'unsupportedFieldWithId',
  [TranslatableString.UnsupportedFieldWithReason]: 'unsupportedFieldWithReason',
  [TranslatableString.UnsupportedFieldWithIdAndReason]: 'unsupportedFieldWithIdAndReason',
  [TranslatableString.FilesInfo]: 'filesInfo',
}

/** Form library texts in the current language; read t at call time so a language switch applies. */
function translateString(str: TranslatableString, params: string[] = []): string {
  const m = t.rjsf[rjsfKeys[str]]
  return typeof m === 'function' ? (m as (...a: string[]) => string)(...params) : m
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
  const pending = useRef<Record<string, string>>({})
  const setPending = useCallback((field: string, text: string) => {
    pending.current[field] = text
  }, [])
  const touch = (id: string) => id && setTouched((x) => (x.includes(id) ? x : [...x, id]))

  const { schema, uiSchema } = useMemo(() => {
    const s = structuredClone(col.schema) as RJSFSchema
    // the page header already carries the collection title; the root object needs no heading
    delete s.title
    delete s.description
    delete s.$schema
    const ui: UiSchema = { 'ui:submitButtonOptions': { norender: true } }
    for (const [field, original] of Object.entries(s.properties ?? {}) as [string, any][]) {
      // the oneOf enum form becomes plain enum for the form library; titles and descriptions follow the language
      const prop = enumForm(original as Prop) as any
      s.properties![field] = prop
      prop.title = fieldTitle(original, field)
      const description = fieldDescription(original)
      if (description) prop.description = description
      else delete prop.description
      if (refItems[field]) {
        ui[field] = { 'ui:widget': prop.type === 'array' ? 'RefManyWidget' : 'RefWidget', 'ui:options': { items: refItems[field] } }
        continue
      }
      switch (fieldKind(prop as Prop, { isKey: !!col.key?.includes(field), soleKey: col.key?.length === 1 && col.key[0] === field, isRef: false, name: field })) {
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
        case 'rows':
          ui[field] = { 'ui:widget': 'RowsWidget' }
          break
        case 'list':
          ui[field] = { 'ui:widget': 'ListWidget' }
          break
        case 'date':
          ui[field] = { 'ui:widget': 'DateWidget' }
          break
        case 'country':
          ui[field] = { 'ui:widget': 'CountryWidget' }
          break
        case 'suggest':
          ui[field] = { 'ui:widget': 'SuggestWidget', 'ui:options': { suggestions: suggestValues(ownRecords ?? [], field) } }
          break
      }
    }
    return { schema: s, uiSchema: ui }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [col, refItems, own?.dataUpdatedAt, locale])

  const extraErrors = useMemo(() => toErrorSchema(serverErrors, schema, col.name), [serverErrors, schema, col.name])

  return (
    <div
      onBlur={(e) => touch((e.target as HTMLElement).id)}
      // keypress, not keydown: the pickers stop keydown from bubbling, and the browser submits the form on the keypress
      onKeyPressCapture={(e) => {
        // Enter in a dropdown picks the highlighted option; it must never submit the form
        if (e.key === 'Enter' && (e.target as HTMLElement).closest('[role="combobox"]')) e.preventDefault()
      }}
    >
    <Form
      id={formId}
      schema={schema}
      uiSchema={uiSchema}
      formData={formData}
      validator={validator}
      widgets={widgets}
      templates={templates}
      formContext={{ touched, all: tried || serverErrors.length > 0, setPending } satisfies FormCtx}
      customValidate={(_data, errors) => {
        // text typed into a list field but not added would be lost on save
        for (const [name, text] of Object.entries(pending.current)) {
          if (text) (errors as any)[name]?.addError(t.form.pendingEntry)
        }
        return errors
      }}
      liveValidate
      disabled={disabled}
      noHtml5Validate
      showErrorList={false}
      transformErrors={(errs) => transformErrors(errs, col.schema as Prop)}
      translateString={translateString}
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
      onError={(errs) => { setTried(true); onInvalid?.(errs.map((e) => (e.property && e.property !== '.' ? `${e.property.replace(/^\./, '')}${t.common.colon}` : '') + (e.message ?? e.stack ?? '')))}}
    />
    </div>
  )
}
