// A stored scalar value as text in the viewer's language: the label of an enum code, the
// placeholder word for `tbd`, a country with its flag. Used where a value is shown as plain
// text, searched or sorted; the codes stay what is stored and exported.
// Imports only relative .ts files so scripts/check-console-logic.mts can test it.
import { t } from '../i18n/index.ts'
import { countryName } from './countryDisplay.ts'
import type { Prop } from './fieldKind.ts'
import { enumLabel, isEnumLike, PLACEHOLDER_TBD } from './labels.ts'

export const isTbd = (v: unknown): v is string => v === PLACEHOLDER_TBD

/** What a scalar value reads as. `prop` is its schema property (may be undefined). */
export function displayText(prop: Prop | undefined, value: unknown, loc?: string): string {
  if (value === undefined || value === null) return ''
  // the array property itself is passed down: enum labels, icons and translations are read from its items and from the array alongside, as labels.ts does
  if (Array.isArray(value)) return value.map((v) => displayText(prop, v, loc)).join(', ')
  if (typeof value !== 'string') return typeof value === 'object' ? JSON.stringify(value) : String(value)
  if (isTbd(value)) return t.placeholder.tbd
  if (prop && isEnumLike(prop)) return enumLabel(prop, value, loc)
  const format = (prop?.format ?? (prop?.items as Prop | undefined)?.format) as string | undefined
  // plain text (links, labels, sorting, search): never the flag emoji, which belongs to rich cells only
  if (format === 'country' && /^[A-Z]{2}$/.test(value)) return countryName(value, loc)
  return value
}
