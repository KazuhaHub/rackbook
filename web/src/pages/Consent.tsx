import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { CircleAlert, PlugZap } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { BrandMark } from '@/components/BrandMark'
import { t } from '@/i18n/zh-CN'
import { errorMessage } from '@/lib/api'
import { consentInfo, decideConsent } from '@/lib/grants'
import { useMeta } from '@/providers/meta'

const C = t.oauth.consent

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_1fr] items-baseline gap-3 border-b py-2.5 text-sm last:border-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  )
}

/**
 * The page an MCP client sends the person to (via /oauth/authorize). It shows who
 * asks, as whom, and where the result goes, and asks every time: nothing is remembered.
 */
export default function Consent() {
  const { meta } = useMeta()
  const [params] = useSearchParams()
  const req = params.get('req') ?? ''
  const q = useQuery({ queryKey: ['rb', 'consent', req], queryFn: () => consentInfo(req), enabled: req !== '', retry: false })
  const [busy, setBusy] = useState<'approve' | 'deny' | null>(null)
  const [sent, setSent] = useState(false)
  const [error, setError] = useState('')
  const name = meta.branding?.name || meta.title || t.appName

  useEffect(() => {
    document.title = `${C.title} · ${name}`
  }, [name])

  const decide = async (approve: boolean) => {
    setError('')
    setBusy(approve ? 'approve' : 'deny')
    try {
      const { redirect } = await decideConsent(req, approve)
      setSent(true)
      window.location.assign(redirect)
    } catch (e) {
      setError(errorMessage(e))
      setBusy(null)
    }
  }

  const info = q.data
  return (
    <div className="flex min-h-svh items-center justify-center bg-muted/40 p-4">
      <div className="rb-page w-full max-w-md">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <BrandMark logo={meta.branding?.logo} name={name} className="size-12 rounded-2xl" />
          <div>
            <h1 className="text-xl font-semibold tracking-tight">{C.title}</h1>
            {info && <p className="mt-1 text-sm text-muted-foreground">{C.subtitle(info.clientName)}</p>}
          </div>
        </div>
        <div className="space-y-4 rounded-2xl border bg-card p-6 shadow-xs">
          {q.isPending && req !== '' ? (
            <Skeleton className="h-40 w-full" />
          ) : q.isError || req === '' ? (
            <Alert variant="destructive">
              <CircleAlert />
              <AlertTitle>{C.title}</AlertTitle>
              <AlertDescription>{req === '' || (q.error as { statusCode?: number } | null)?.statusCode === 404 ? C.expired : errorMessage(q.error)}</AlertDescription>
            </Alert>
          ) : info ? (
            <>
              <dl>
                <Row label={C.client}>
                  <span className="flex items-center gap-2 font-medium">
                    <PlugZap className="size-4 shrink-0 text-muted-foreground" />
                    {info.clientName}
                  </span>
                  <span className="mt-0.5 block font-mono text-xs break-all text-muted-foreground" title={C.clientId}>
                    {info.clientId}
                  </span>
                </Row>
                <Row label={C.redirect}>
                  <span className="font-mono text-[0.8125rem] font-semibold break-all">{info.redirectHost}</span>
                  <span className="mt-0.5 block text-xs text-muted-foreground">{C.redirectHint}</span>
                  {info.punycode && (
                    <span role="alert" className="mt-1.5 block rounded-md bg-amber-500/15 px-2.5 py-1.5 text-xs text-amber-800 dark:text-amber-300">
                      {C.punycode}
                    </span>
                  )}
                </Row>
                <Row label={C.user}>
                  <span className="font-mono text-[0.8125rem]">{info.user.id}</span>
                </Row>
                <Row label={C.access}>{info.canWrite ? C.write : C.read}</Row>
              </dl>
              <p className="text-xs text-muted-foreground">{C.expiryHint}</p>
              {error && <p className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</p>}
              <div className="flex gap-2">
                <Button variant="outline" className="h-10 flex-1" disabled={busy !== null || sent} onClick={() => void decide(false)}>
                  {C.deny}
                </Button>
                <Button className="h-10 flex-1" disabled={busy !== null || sent} onClick={() => void decide(true)}>
                  {sent ? C.sent : busy === 'approve' ? C.working : C.approve}
                </Button>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </div>
  )
}
