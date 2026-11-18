import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { CircleAlert, Fingerprint, KeyRound, LogOut, ShieldX } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { BrandMark } from '@/components/BrandMark'
import { Skeleton } from '@/components/ui/skeleton'
import { t } from '@/i18n/zh-CN'
import type { LoginConfig } from '@/lib/auth'
import { getCredential, isCancelled, passkeysSupported } from '@/lib/webauthn'

const L = t.auth.login

async function loadConfig(): Promise<LoginConfig> {
  const res = await fetch('/auth/config', { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error('config')
  return res.json()
}

async function post(url: string, body: unknown): Promise<{ ok: boolean; status: number; data: any }> {
  const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
  return { ok: res.ok, status: res.status, data: await res.json().catch(() => null) }
}

export default function Login() {
  const [params] = useSearchParams()
  const code = params.get('error') ?? ''
  const ret = params.get('return') ?? ''
  const { data: cfg, isPending } = useQuery({ queryKey: ['auth', 'config'], queryFn: loadConfig, retry: 1 })
  const [redirecting, setRedirecting] = useState(false)
  const [passkeyState, setPasskeyState] = useState<'idle' | 'working'>('idle')
  const [passkeyError, setPasskeyError] = useState('')

  const name = cfg?.name || t.appName
  useEffect(() => {
    document.title = `${L.title} · ${name}`
  }, [name])

  const start = '/auth/oidc/start' + (ret ? `?return=${encodeURIComponent(ret)}` : '')
  const known = L.errors[code]
  const loggedOut = code === 'logged_out'
  const blocked = code === 'no_role' || code === 'tenant'

  const loginWithPasskey = async () => {
    setPasskeyError('')
    setPasskeyState('working')
    try {
      const begin = await post('/auth/passkey/begin', {})
      if (!begin.ok) throw new Error('begin')
      const assertion = await getCredential(begin.data.options)
      const fin = await post(
        `/auth/passkey/finish?ceremony=${encodeURIComponent(begin.data.ceremony)}${ret ? `&return=${encodeURIComponent(ret)}` : ''}`,
        assertion,
      )
      if (!fin.ok) {
        setPasskeyError(fin.data?.error === 'no_role' ? L.passkeyNoRole : L.passkeyFailed)
        return
      }
      window.location.assign(fin.data?.return || '/')
    } catch (e) {
      setPasskeyError(isCancelled(e) ? L.passkeyCancelled : L.passkeyFailed)
    } finally {
      setPasskeyState('idle')
    }
  }

  return (
    <div className="flex min-h-svh items-center justify-center bg-muted/40 p-4">
      <div className="rb-page w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <BrandMark logo={cfg?.logo} name={name} className="size-12 rounded-2xl" />
          <div>
            <h1 className="text-xl font-semibold tracking-tight">{name}</h1>
            <p className="mt-1 text-sm text-muted-foreground">{L.subtitle}</p>
          </div>
        </div>

        <div className="space-y-4 rounded-2xl border bg-card p-6 shadow-xs">
          {loggedOut && (
            <Alert>
              <LogOut />
              <AlertTitle>{L.loggedOutTitle}</AlertTitle>
              <AlertDescription>{L.loggedOutBody}</AlertDescription>
            </Alert>
          )}
          {known && (
            <Alert variant="destructive" className="rb-row-in">
              {blocked ? <ShieldX /> : <CircleAlert />}
              <AlertTitle>{known.title}</AlertTitle>
              <AlertDescription>{known.body}</AlertDescription>
            </Alert>
          )}
          {!loggedOut && code && !known && (
            <Alert variant="destructive">
              <CircleAlert />
              <AlertTitle>{L.errors.bad_callback.title}</AlertTitle>
              <AlertDescription>{L.errors.bad_callback.body}</AlertDescription>
            </Alert>
          )}

          {isPending ? (
            <Skeleton className="h-9 w-full" />
          ) : (
            <Button
              size="lg"
              className="h-10 w-full"
              render={<a href={start} onClick={() => setRedirecting(true)} />}
              aria-busy={redirecting}
            >
              <KeyRound />
              {redirecting ? L.redirecting : cfg?.label || L.oidc}
            </Button>
          )}

          {cfg?.passkeys && (
            <>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="h-px flex-1 bg-border" />
                {L.or}
                <span className="h-px flex-1 bg-border" />
              </div>
              <Button
                variant="outline"
                size="lg"
                className="h-10 w-full"
                disabled={passkeyState === 'working' || !passkeysSupported()}
                onClick={loginWithPasskey}
              >
                <Fingerprint />
                {passkeyState === 'working' ? L.passkeyWorking : L.passkey}
              </Button>
              {!passkeysSupported() && <p className="text-center text-xs text-muted-foreground">{L.passkeyUnsupported}</p>}
              {passkeyError && (
                <p role="alert" className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  {passkeyError}
                </p>
              )}
            </>
          )}
        </div>
        <p className="mt-4 text-center text-xs text-muted-foreground">{L.footer}</p>
      </div>
    </div>
  )
}
