import { useEffect } from 'react'
import { useSearchParams } from 'react-router'
import { AuthShell } from '@/components/AuthShell'
import { LocalSignInForm } from '@/components/LocalSignInForm'
import { t } from '@/i18n'
import { safeReturn, useAuthConfig } from '@/lib/localAuth'
import { syncLocale } from '@/lib/locale'

// Re-authentication of a local account (docs/design-local-accounts.md, 5.7): the one-step form again, for the person who
// is signed in. Three failures end every session of the account.
export default function LocalReauth() {
  const [params] = useSearchParams()
  const ret = safeReturn(params.get('return'))
  const { data: cfg } = useAuthConfig()
  useEffect(() => {
    if (cfg) void syncLocale({ detected: cfg.locale, fallback: cfg.defaultLocale }).catch(() => {})
  }, [cfg])
  useEffect(() => {
    document.title = `${t.auth.local.reauth.title} · ${cfg?.name || t.appName}`
  }, [cfg?.name])
  return (
    <AuthShell cfg={cfg} subtitle={t.auth.local.reauth.subtitle}>
      {params.get('return') && <p className="text-sm text-muted-foreground">{t.auth.local.reauth.reason}</p>}
      <LocalSignInForm kind="reauth" ret={ret} autoFocus />
    </AuthShell>
  )
}
