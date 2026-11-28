import { useState, type FormEvent } from 'react'
import { Fingerprint, LogIn } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { t } from '@/i18n'
import { errorText, postJSON, safeReturn } from '@/lib/localAuth'
import { getCredential, isCancelled, passkeysSupported } from '@/lib/webauthn'

type Props = {
  /** login asks for the username; reauth is for the person who is signed in */
  kind: 'login' | 'reauth'
  ret: string
  autoFocus?: boolean
  /** called with the page to go to, after the server has set the session */
  onDone?: (to: string) => void
}

/**
 * The one-step form: username, password and the second factor in one request, one answer for every failure
 * ("Username, password or code is wrong"): it never says which part was wrong.
 */
export function LocalSignInForm({ kind, ret, autoFocus, onDone }: Props) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [withPasskey, setWithPasskey] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const url = kind === 'login' ? '/auth/local/login' : '/auth/local/reauth'
  const L = t.auth.local

  const finish = (to: unknown) => {
    const dest = safeReturn(to)
    if (onDone) onDone(dest)
    else window.location.assign(dest)
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    try {
      const body: Record<string, unknown> = { password, return: ret }
      if (kind === 'login') body.username = username
      if (withPasskey) {
        const begin = await postJSON('/auth/local/attempt', {})
        if (!begin.ok) {
          setError(errorText(begin.data.error))
          return
        }
        body.attempt = begin.data.attempt
        try {
          body.passkey = await getCredential(begin.data.passkey)
        } catch (err) {
          setError(isCancelled(err) ? L.passkeyCancelled : L.passkeyFailed)
          return
        }
      } else {
        body.code = code
      }
      const res = await postJSON(url, body)
      if (res.ok) {
        finish(res.data.return)
        return
      }
      if (res.status === 401 && res.data.error === 'login_required' && kind === 'reauth') {
        window.location.assign('/auth/login?return=' + encodeURIComponent(ret))
        return
      }
      setError(errorText(res.data.error))
      setCode('')
    } finally {
      setBusy(false)
    }
  }

  const label = kind === 'login' ? L.signIn : t.auth.local.reauth.submit
  const working = kind === 'login' ? L.signingIn : t.auth.local.reauth.working
  return (
    <form onSubmit={submit} className="space-y-3" noValidate>
      {kind === 'login' && (
        <div className="space-y-1.5">
          <Label htmlFor="ls-user">{L.username}</Label>
          <Input
            id="ls-user"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            autoFocus={autoFocus}
            required
          />
        </div>
      )}
      <div className="space-y-1.5">
        <Label htmlFor="ls-pass">{L.password}</Label>
        <Input id="ls-pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
      </div>
      {!withPasskey ? (
        <div className="space-y-1.5">
          <Label htmlFor="ls-code">{L.code}</Label>
          <Input
            id="ls-code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="123456"
            aria-describedby="ls-code-hint"
            className="tracking-widest tabular-nums"
          />
          <p id="ls-code-hint" className="text-xs text-muted-foreground">
            {L.codeHint}
          </p>
        </div>
      ) : (
        <p className="rounded-md bg-muted px-3 py-2 text-sm text-muted-foreground">{busy ? L.passkeyWorking : L.passkeyHint}</p>
      )}
      {error && (
        <p role="alert" className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" size="lg" className="h-10 w-full" disabled={busy} aria-busy={busy}>
        <LogIn />
        {busy ? working : label}
      </Button>
      {passkeysSupported() ? (
        <Button
          type="button"
          variant="ghost"
          className="w-full"
          disabled={busy}
          onClick={() => {
            setWithPasskey((v) => !v)
            setError('')
          }}
        >
          <Fingerprint />
          {withPasskey ? L.useCode : L.usePasskey}
        </Button>
      ) : null}
    </form>
  )
}
