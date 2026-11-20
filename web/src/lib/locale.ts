// Which language the console shows, and remembering the person's choice.
//
// Order: the signed-in person's saved preference (server) -> the choice saved in
// this browser (localStorage) -> the server's match of Accept-Language -> the
// configured default -> zh-CN. Only an explicit choice (or a saved server
// preference) is written to localStorage; a detected language is not, so a
// browser whose language changes keeps following it.
import { activateLocale, DEFAULT_LOCALE, locale, normalizeLocale, type Locale } from '@/i18n'
import { apiFetch } from './api'

const KEY = 'rackbook.locale'

export function storedLocale(): Locale | null {
  try {
    return normalizeLocale(window.localStorage.getItem(KEY))
  } catch {
    return null
  }
}

function store(l: Locale) {
  try {
    window.localStorage.setItem(KEY, l)
  } catch {
    // private window or storage blocked: the choice lasts for this page only
  }
}

/**
 * The console saves the choice on the server for a person the server tells
 * apart: a login or a Cloudflare Access identity. Under --auth none everyone
 * shares one identity (or none), so the choice stays in each browser.
 */
export const canSavePreference = (user?: { authMethod?: string; id?: string } | null) =>
  !!user?.id && (user.authMethod === 'oidc' || user.authMethod === 'passkey' || user.authMethod === 'cloudflare-access')

type Sources = { server?: string | null; detected?: string | null; fallback?: string | null }

/** The language to show given what is known so far. */
export function resolveLocale({ server, detected, fallback }: Sources): Locale {
  return (
    normalizeLocale(server) ?? storedLocale() ?? normalizeLocale(detected) ?? normalizeLocale(fallback) ?? DEFAULT_LOCALE
  )
}

/** Before the first render: the browser's saved choice, so most visits never flash another language. */
export async function bootLocale(): Promise<void> {
  const l = storedLocale()
  if (l && l !== locale) {
    try {
      await activateLocale(l)
    } catch {
      // the chunk did not load: start in the default and let the sync retry
    }
  }
}

/**
 * Applies what the server said (meta or the login config). A saved server
 * preference is also copied to this browser for the next visit.
 */
export async function syncLocale(src: Sources): Promise<void> {
  // a choice is being saved: what the server says now may predate it
  if (saving) return
  const server = normalizeLocale(src.server)
  if (server) store(server)
  const want = resolveLocale(src)
  if (want !== locale) await activateLocale(want)
  // scripts/check-i18n-dom.mts switches only after this, or the server's answer could undo its switch
  if (import.meta.env.DEV) (window as unknown as Record<string, unknown>).__rbLocaleSynced = true
}

/** The chosen language could not be shown (its messages did not load); nothing changed. */
export class LocaleLoadError extends Error {}

/**
 * The person picked a language: show it, remember it in this browser and, for a
 * signed-in person, on the server. Rejects with LocaleLoadError when it could
 * not be shown (nothing is stored then), or with the API error when the server
 * could not save it (the language is shown and remembered in this browser).
 */
let saving = 0

export async function chooseLocale(l: Locale, saveOnServer: boolean): Promise<void> {
  saving++
  try {
    let applied: boolean
    try {
      applied = await activateLocale(l)
    } catch (e) {
      throw new LocaleLoadError(String(e))
    }
    // another pick came after this one: that one is stored and saved
    if (!applied) return
    store(l)
    if (saveOnServer) {
      await apiFetch<{ locale: string }>('/account/preferences', { method: 'PUT', body: JSON.stringify({ locale: l }) })
    }
  } finally {
    saving--
  }
}
