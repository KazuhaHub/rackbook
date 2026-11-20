import { Fragment, useCallback, useEffect, useSyncExternalStore, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Check, Languages } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { locale, LOCALE_NAMES, LOCALES, normalizeLocale, subscribeLocale, t, type Locale } from '@/i18n'
import { canSavePreference, chooseLocale, LocaleLoadError, syncLocale } from '@/lib/locale'
import { metaQuery } from '@/providers/meta'
import type { Meta, MetaUser } from '@/lib/types'

export function useLocale(): Locale {
  return useSyncExternalStore(subscribeLocale, () => locale, () => locale)
}

/**
 * Remounts its children when the language changes, so that nothing computed
 * from the old messages (memoised values, state initialised from t) survives.
 * Unsaved input inside is reset; the switch lives in menus, away from forms.
 */
export function LocaleBoundary({ children }: { children: ReactNode }) {
  const l = useLocale()
  return <Fragment key={l}>{children}</Fragment>
}

/** Applies the language the server knows about (saved preference, Accept-Language match). */
export function LocaleSync({ meta }: { meta: Meta }) {
  const server = meta.user?.locale
  const detected = meta.locale
  const fallback = meta.defaultLocale
  useEffect(() => {
    void syncLocale({ server, detected, fallback }).catch(() => {})
  }, [server, detected, fallback])
  // scripts/check-i18n-dom.mts switches the language through the same path as the menu
  const choose = useChoose(canSavePreference(meta.user))
  useEffect(() => {
    if (!import.meta.env.DEV) return
    const w = window as unknown as Record<string, unknown>
    const before = w.__rbChooseLocale
    w.__rbChooseLocale = async (l: string) => {
      const n = normalizeLocale(l)
      if (!n) throw new Error(`unsupported ${l}`)
      await choose(n)
    }
    return () => {
      w.__rbChooseLocale = before
    }
  }, [choose])
  return null
}

function useChoose(saveOnServer: boolean) {
  const qc = useQueryClient()
  return useCallback(
    async (l: Locale) => {
      const before = qc.getQueryData<Meta>(metaQuery.queryKey)?.user?.locale
      const setCached = (v: string | undefined) =>
        qc.setQueryData<Meta>(metaQuery.queryKey, (m) => (m?.user ? { ...m, user: { ...m.user, locale: v } } : m))
      // keep the cached preference in step, or LocaleSync would switch back
      if (saveOnServer) setCached(l)
      try {
        await chooseLocale(l, saveOnServer)
        // a meta fetched while saving may hold the old choice
        if (saveOnServer) await qc.invalidateQueries({ queryKey: metaQuery.queryKey })
      } catch (e) {
        if (e instanceof LocaleLoadError) {
          if (saveOnServer) setCached(before)
          toast.error(t.language.loadFailed)
        } else {
          toast.error(t.language.saveFailed)
        }
      }
    },
    [qc, saveOnServer],
  )
}

function Items({ onPick }: { onPick: (l: Locale) => void }) {
  const current = useLocale()
  return (
    <>
      {LOCALES.map((l) => (
        <DropdownMenuItem key={l} lang={l} onClick={() => onPick(l)} aria-checked={l === current} role="menuitemradio">
          <Check className={l === current ? '' : 'invisible'} />
          {LOCALE_NAMES[l]}
        </DropdownMenuItem>
      ))}
    </>
  )
}

/** A submenu for the user menu. */
export function LanguageSubmenu({ user }: { user?: MetaUser | null }) {
  const pick = useChoose(canSavePreference(user))
  return (
    <DropdownMenuSub>
      <DropdownMenuSubTrigger>
        <Languages /> {t.language.label}
        <span className="ml-auto pl-2 text-xs text-muted-foreground">{LOCALE_NAMES[locale]}</span>
      </DropdownMenuSubTrigger>
      <DropdownMenuSubContent className="min-w-36">
        <Items onPick={pick} />
      </DropdownMenuSubContent>
    </DropdownMenuSub>
  )
}

/** A stand-alone button, for pages without the user menu (login, no session). */
export function LanguageToggle({ user }: { user?: MetaUser | null }) {
  const pick = useChoose(canSavePreference(user))
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" size="icon" aria-label={t.language.label} title={t.language.label} />}>
        <Languages className="size-4" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-36">
        <Items onPick={pick} />
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
