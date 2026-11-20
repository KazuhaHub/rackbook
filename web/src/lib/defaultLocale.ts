import { DEFAULT_LOCALE, LOCALES, normalizeLocale, type Locale } from '@/i18n'
import { useMeta } from '@/providers/meta'

/** The language the standard text of the ledger is written in (rackbook.yml i18n.default). */
export function useDefaultLocale(): Locale {
  return normalizeLocale(useMeta().meta.defaultLocale) ?? DEFAULT_LOCALE
}

/** The supported languages other than the default one. */
export function useOtherLocales(): Locale[] {
  const def = useDefaultLocale()
  return LOCALES.filter((l) => l !== def)
}
