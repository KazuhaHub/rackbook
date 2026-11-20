// Country codes as people read them: a flag and a name in the viewer's language.
// Imports only relative .ts files so scripts/check-console-logic.mts can test it.
import { locale } from '../i18n/index.ts'

/** The flag emoji of an upper-case alpha-2 code (two regional indicator symbols); '' for anything else. */
export function flagEmoji(code: string): string {
  if (!/^[A-Z]{2}$/.test(code)) return ''
  return String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}

const names = new Map<string, Intl.DisplayNames | null>()

/** The country name in a language (default: the current one); the code itself when the runtime does not know it. */
export function countryName(code: string, loc: string = locale): string {
  let dn = names.get(loc)
  if (dn === undefined) {
    try {
      dn = new Intl.DisplayNames([loc], { type: 'region' })
    } catch {
      dn = null
    }
    names.set(loc, dn)
  }
  try {
    return dn?.of(code) ?? code
  } catch {
    return code
  }
}

/** The country part of a subdivision code ("US-OR" -> "US"); undefined when it has none. */
export function subdivisionCountry(code: string): string | undefined {
  const m = /^([A-Z]{2})-/.exec(code)
  return m ? m[1] : undefined
}
