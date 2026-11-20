// The console's copy in every supported language, and the current one.
//
// `t` is a live binding: importers always see the current language's messages
// as long as they read `t.x.y` when they render. Reading it at module load
// (`const M = t.auth.menu` at the top of a file) freezes the language of that
// moment; scripts/check-i18n.mts rejects that.
//
// zh-CN is the reference: its shape is the Messages type, the other languages
// are checked against it by the compiler (`satisfies Messages`) and merged
// over it at run time, so a gap shows the Chinese text instead of nothing.
import zhCN, { type Messages } from './zh-CN.ts'

export type { Messages }

export const LOCALES = ['zh-CN', 'zh-TW', 'en-US'] as const
export type Locale = (typeof LOCALES)[number]
export const DEFAULT_LOCALE: Locale = 'zh-CN'

/** Each language's name in that language (never translated). */
export const LOCALE_NAMES: Record<Locale, string> = {
  'zh-CN': '简体中文',
  'zh-TW': '繁體中文',
  'en-US': 'English',
}

const loaders: Record<Locale, () => Promise<{ default: Messages }>> = {
  'zh-CN': async () => ({ default: zhCN }),
  'zh-TW': () => import('./zh-TW.ts'),
  'en-US': () => import('./en-US.ts'),
}

export let t: Messages = zhCN
export let locale: Locale = DEFAULT_LOCALE

/** The supported locale for a tag (case-insensitive, aliases as the server's internal/locale). */
export function normalizeLocale(tag: string | null | undefined): Locale | null {
  if (!tag) return null
  const s = tag.trim().replace(/_/g, '-').toLowerCase()
  for (const l of LOCALES) if (l.toLowerCase() === s) return l
  if (s === 'zh' || s === 'zh-hans' || s.startsWith('zh-hans-') || s === 'zh-sg') return 'zh-CN'
  if (s === 'zh-hant' || s.startsWith('zh-hant-') || s === 'zh-hk' || s === 'zh-mo') return 'zh-TW'
  if (s === 'en' || s.startsWith('en-')) return 'en-US'
  return null
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** base with every key of over that has a value; nested objects are merged. */
export function mergeMessages<T>(base: T, over: unknown): T {
  if (!isObject(base) || !isObject(over)) return (over ?? base) as T
  const out: Record<string, unknown> = { ...base }
  for (const [k, v] of Object.entries(over)) {
    if (v === undefined || v === null) continue
    out[k] = isObject(out[k]) && isObject(v) ? mergeMessages(out[k], v) : v
  }
  return out as T
}

const cache = new Map<Locale, Messages>([['zh-CN', zhCN]])

/** Loads (once) the messages of a language, with zh-CN filling any gap. */
export async function loadMessages(l: Locale): Promise<Messages> {
  const hit = cache.get(l)
  if (hit) return hit
  const mod = await loaders[l]()
  const m = mergeMessages(zhCN, mod.default)
  cache.set(l, m)
  return m
}

type Listener = () => void
const listeners = new Set<Listener>()

/** Calls fn after every language change; returns the unsubscribe function. */
export function subscribeLocale(fn: Listener): () => void {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

let activation = 0

/**
 * Makes l the current language once its messages are in place. Resolves to
 * false when a later call overtook this one (the later language wins,
 * whichever loads first).
 */
export async function activateLocale(l: Locale): Promise<boolean> {
  const mine = ++activation
  const m = await loadMessages(l)
  if (mine !== activation) return false
  if (l === locale && m === t) return true
  t = m
  locale = l
  if (typeof document !== 'undefined') document.documentElement.lang = l
  for (const fn of listeners) fn()
  return true
}
