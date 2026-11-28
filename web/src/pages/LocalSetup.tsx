import { useEffect, useState, type FormEvent } from 'react'
import { Check, CircleAlert, Copy, Fingerprint, KeyRound, ShieldCheck, Smartphone } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { AuthShell } from '@/components/AuthShell'
import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { errorText, postJSON, safeReturn, useAuthConfig } from '@/lib/localAuth'
import { createCredential, getCredential, isCancelled, passkeysSupported } from '@/lib/webauthn'
import { syncLocale } from '@/lib/locale'

// The page of an invite or reset link (docs/design-local-accounts.md, 5.2 to 5.5 and 5.8). The one-time token is in the URL
// fragment: it is read, removed from the address with history.replaceState, and kept in memory. Nothing is sent until
// the person presses Continue.

type Info = {
  kind: 'invite' | 'reset'
  scope: 'password' | 'second_factor' | 'all'
  username: string
  name: string
  minLength: number
  expires: string
  newPassword: boolean
  currentPassword: boolean
  newFactor: boolean
  proveFactor: boolean
  proveWith: string[]
}

type Phase = { name: 'missing' } | { name: 'ready' } | { name: 'opening' } | { name: 'form'; info: Info } | { name: 'error'; code: string } | { name: 'done'; signedIn: boolean; ret: string }

// The link is read once, when the page loads (React may run an initializer twice, so the first read is kept), and taken out
// of the address in an effect.
let captured: string | null = null
function takeToken(): string {
  if (captured === null) captured = window.location.hash.replace(/^#/, '')
  return captured
}

export default function LocalSetup() {
  const { data: cfg } = useAuthConfig()
  const [token] = useState(takeToken)
  const [phase, setPhase] = useState<Phase>(() => (token ? { name: 'ready' } : { name: 'missing' }))

  useEffect(() => {
    if (cfg) void syncLocale({ detected: cfg.locale, fallback: cfg.defaultLocale }).catch(() => {})
  }, [cfg])
  useEffect(() => {
    document.title = `${t.auth.local.setup.title} · ${cfg?.name || t.appName}`
  }, [cfg?.name])
  useEffect(() => {
    // nothing of the link stays in the address bar or the history
    if (window.location.hash) window.history.replaceState(null, '', window.location.pathname + window.location.search)
  }, [])

  const S = t.auth.local.setup
  const open = async () => {
    setPhase({ name: 'opening' })
    const r = await postJSON<Info & { error?: string }>('/auth/local/setup/open', { token })
    if (r.ok) setPhase({ name: 'form', info: r.data })
    else setPhase({ name: 'error', code: String(r.data.error ?? 'internal') })
  }

  return (
    <AuthShell cfg={cfg} subtitle={S.subtitle}>
      {phase.name === 'missing' && (
        <Alert variant="destructive">
          <CircleAlert />
          <AlertTitle>{S.missingTitle}</AlertTitle>
          <AlertDescription>{S.missingBody}</AlertDescription>
        </Alert>
      )}
      {(phase.name === 'ready' || phase.name === 'opening') && (
        <>
          <p className="text-sm text-muted-foreground">{S.linkBody}</p>
          <Button size="lg" className="h-10 w-full" onClick={open} disabled={phase.name === 'opening'} aria-busy={phase.name === 'opening'}>
            <KeyRound />
            {phase.name === 'opening' ? S.opening : S.continue}
          </Button>
        </>
      )}
      {phase.name === 'error' && <LinkError code={phase.code} />}
      {phase.name === 'form' && <SetupForm info={phase.info} token={token} onDone={(signedIn, ret) => setPhase({ name: 'done', signedIn, ret })} onLinkError={(code) => setPhase({ name: 'error', code })} />}
      {phase.name === 'done' && <Done signedIn={phase.signedIn} ret={phase.ret} />}
    </AuthShell>
  )
}

function LinkError({ code }: { code: string }) {
  const known = t.auth.local.setup.errors[code]
  if (!known) {
    return (
      <Alert variant="destructive">
        <CircleAlert />
        <AlertTitle>{errorText(code)}</AlertTitle>
      </Alert>
    )
  }
  return (
    <Alert variant="destructive" className="rb-row-in">
      <CircleAlert />
      <AlertTitle>{known.title}</AlertTitle>
      <AlertDescription>{known.body}</AlertDescription>
    </Alert>
  )
}

function Done({ signedIn, ret }: { signedIn: boolean; ret: string }) {
  const S = t.auth.local.setup
  useEffect(() => {
    if (signedIn) window.location.assign(ret)
  }, [signedIn, ret])
  return (
    <div className="space-y-3">
      <Alert>
        <ShieldCheck />
        <AlertTitle>{S.doneTitle}</AlertTitle>
        <AlertDescription>{signedIn ? S.doneBody : S.doneNoRole}</AlertDescription>
      </Alert>
      {!signedIn && (
        <Button className="w-full" render={<a href="/auth/login" />}>
          {S.signInLink}
        </Button>
      )}
    </div>
  )
}

type Factor = 'totp' | 'passkey'

function SetupForm({ info, token, onDone, onLinkError }: { info: Info; token: string; onDone: (signedIn: boolean, ret: string) => void; onLinkError: (code: string) => void }) {
  const S = t.auth.local.setup
  const [password, setPassword] = useState('')
  const [again, setAgain] = useState('')
  const [current, setCurrent] = useState('')
  const [proofCode, setProofCode] = useState('')
  const [factor, setFactor] = useState<Factor>('totp')
  const [totp, setTotp] = useState<{ enrol: string; secret: string; uri: string } | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [passkey, setPasskey] = useState<{ ceremony: string; credential: unknown } | null>(null)
  const [passkeyName, setPasskeyName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [proofPasskey, setProofPasskey] = useState(false)

  // the authenticator secret is made when the person looks at that tab, once
  useEffect(() => {
    if (!info.newFactor || factor !== 'totp' || totp) return
    let live = true
    void postJSON<{ enrol: string; secret: string; uri: string; error?: string }>('/auth/local/setup/totp', { token }).then((r) => {
      if (!live) return
      if (r.ok) setTotp(r.data)
      else if (r.status === 404 || r.status === 409 || r.status === 410) onLinkError(String(r.data.error))
      else setError(errorText(r.data.error))
    })
    return () => {
      live = false
    }
  }, [info.newFactor, factor, totp, token, onLinkError])

  const addPasskey = async () => {
    setBusy(true)
    setError('')
    try {
      const begin = await postJSON<{ ceremony: string; options: { publicKey: Record<string, any> }; error?: string }>('/auth/local/setup/passkey', { token })
      if (!begin.ok) {
        setError(errorText(begin.data.error))
        return
      }
      try {
        const credential = await createCredential(begin.data.options)
        setPasskey({ ceremony: begin.data.ceremony, credential })
      } catch (e) {
        setError(isCancelled(e) ? t.auth.local.passkeyCancelled : S.passkeyFailed)
      }
    } finally {
      setBusy(false)
    }
  }

  const copy = async () => {
    if (!totp) return
    try {
      await navigator.clipboard.writeText(totp.secret)
      setCopied(true)
    } catch {
      // clipboard blocked: the secret is on screen to be typed
    }
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy) return
    setError('')
    if (info.newPassword) {
      if (password.length < info.minLength) return setError(S.tooShort(info.minLength))
      if (password !== again) return setError(S.mismatch)
    }
    const body: Record<string, unknown> = { token }
    if (info.newPassword) body.password = password
    if (info.currentPassword) body.current_password = current
    if (info.newFactor) {
      if (factor === 'totp' && totp && totpCode) body.totp = { enrol: totp.enrol, code: totpCode }
      else if (factor === 'passkey' && passkey) body.passkey = { ceremony: passkey.ceremony, credential: passkey.credential, name: passkeyName }
      else return setError(S.factorRequired)
    }
    setBusy(true)
    try {
      if (info.proveFactor) {
        if (proofPasskey) {
          const begin = await postJSON('/auth/local/attempt', {})
          if (!begin.ok) return setError(errorText(begin.data.error))
          try {
            body.proof = { attempt: begin.data.attempt, passkey: await getCredential(begin.data.passkey) }
          } catch (err) {
            return setError(isCancelled(err) ? t.auth.local.passkeyCancelled : t.auth.local.passkeyFailed)
          }
        } else body.proof = { code: proofCode }
      }
      const r = await postJSON('/auth/local/setup/finish', body)
      if (r.ok) {
        onDone(!!r.data.signedIn, safeReturn('/'))
        return
      }
      const code = String(r.data.error ?? 'internal')
      if (code === 'invite_invalid' || code === 'invite_expired' || code === 'invite_claimed') return onLinkError(code)
      if (code === 'password_rules') {
        const rule = String(r.data.rule ?? '')
        return setError(rule === 'too_short' ? S.tooShort(Number(r.data.min) || info.minLength) : S.rules[rule] ?? S.rules.too_short)
      }
      if (code === 'bad_code') return setError(S.badCode)
      if (code === 'passkey_failed') return setError(S.passkeyFailed)
      if (code === 'factor_required') return setError(S.factorRequired)
      setError(errorText(code))
      setProofCode('')
    } finally {
      setBusy(false)
    }
  }

  const scope = info.kind === 'invite' ? 'invite' : info.scope
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <p className="text-sm text-muted-foreground">{(S.intro[scope] ?? S.intro.all)(info.name, info.username)}</p>
      <input type="text" name="username" value={info.username} autoComplete="username" readOnly hidden aria-hidden />

      {info.currentPassword && (
        <Field id="su-current" label={S.currentPassword}>
          <Input id="su-current" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
        </Field>
      )}

      {info.proveFactor && (
        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">{S.proveTitle}</legend>
          <p className="text-xs text-muted-foreground">{S.proveBody}</p>
          {!proofPasskey && info.proveWith.includes('totp') && (
            <Input aria-label={t.auth.local.code} value={proofCode} onChange={(e) => setProofCode(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="123456" className="tracking-widest tabular-nums" />
          )}
          {info.proveWith.includes('passkey') && passkeysSupported() && (
            <Button type="button" variant="outline" className="w-full" onClick={() => setProofPasskey((v) => !v)}>
              <Fingerprint />
              {proofPasskey ? t.auth.local.useCode : t.auth.local.usePasskey}
            </Button>
          )}
        </fieldset>
      )}

      {info.newPassword && (
        <>
          <Field id="su-pass" label={S.newPassword} hint={S.passwordHint(info.minLength)}>
            <Input id="su-pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={info.minLength} required />
          </Field>
          <Field id="su-again" label={S.confirmPassword}>
            <Input id="su-again" type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required />
          </Field>
        </>
      )}

      {info.newFactor && (
        <fieldset className="space-y-3">
          <legend className="text-sm font-medium">{S.factorTitle}</legend>
          <p className="text-xs text-muted-foreground">{S.factorBody}</p>
          <div role="tablist" className="grid grid-cols-2 gap-1 rounded-lg bg-muted p-1">
            {(['totp', 'passkey'] as const).map((f) => (
              <button
                key={f}
                type="button"
                role="tab"
                aria-selected={factor === f}
                onClick={() => setFactor(f)}
                className={`flex items-center justify-center gap-1.5 rounded-md px-2 py-1.5 text-sm ${factor === f ? 'bg-background font-medium shadow-xs' : 'text-muted-foreground'}`}
              >
                {f === 'totp' ? <Smartphone className="size-4" /> : <Fingerprint className="size-4" />}
                {f === 'totp' ? S.totpTab : S.passkeyTab}
              </button>
            ))}
          </div>
          {factor === 'totp' && (
            <div className="space-y-3">
              <p className="text-sm">{S.totpBody}</p>
              {totp ? (
                <>
                  <div className="space-y-1.5">
                    <Label htmlFor="su-secret">{S.totpSecret}</Label>
                    <div className="flex gap-2">
                      <Input id="su-secret" readOnly value={totp.secret} className="font-mono text-xs" onFocus={(e) => e.currentTarget.select()} />
                      <Button type="button" variant="outline" onClick={copy}>
                        {copied ? <Check /> : <Copy />}
                        {copied ? S.copied : S.copy}
                      </Button>
                    </div>
                    <a className="text-xs text-primary underline-offset-4 hover:underline" href={totp.uri}>
                      {S.openApp}
                    </a>
                  </div>
                  <Field id="su-totp" label={S.totpCode}>
                    <Input id="su-totp" value={totpCode} onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="123456" className="tracking-widest tabular-nums" />
                  </Field>
                </>
              ) : (
                <p className="text-sm text-muted-foreground">{S.preparing}</p>
              )}
            </div>
          )}
          {factor === 'passkey' && (
            <div className="space-y-3">
              <p className="text-sm">{S.passkeyBody}</p>
              {!passkeysSupported() ? (
                <p className="text-xs text-muted-foreground">{t.auth.local.passkeyUnsupported}</p>
              ) : passkey ? (
                <p className="flex items-center gap-1.5 text-sm text-emerald-600 dark:text-emerald-400">
                  <Check className="size-4" />
                  {S.passkeyAdded}
                </p>
              ) : (
                <>
                  <Field id="su-pkname" label={S.passkeyName}>
                    <Input id="su-pkname" value={passkeyName} onChange={(e) => setPasskeyName(e.target.value)} maxLength={60} autoComplete="off" />
                  </Field>
                  <Button type="button" variant="outline" className="w-full" onClick={addPasskey} disabled={busy}>
                    <Fingerprint />
                    {busy ? t.auth.local.passkeyWorking : S.passkeyAdd}
                  </Button>
                </>
              )}
            </div>
          )}
        </fieldset>
      )}

      {error && (
        <p role="alert" className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" size="lg" className="h-10 w-full" disabled={busy} aria-busy={busy}>
        <ShieldCheck />
        {busy ? S.finishing : S.finish}
      </Button>
      {info.expires && <p className="text-center text-xs text-muted-foreground">{S.expires(formatDateTime(info.expires))}</p>}
    </form>
  )
}

function Field({ id, label, hint, children }: { id: string; label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}
