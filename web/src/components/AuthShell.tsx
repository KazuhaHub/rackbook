import type { ReactNode } from 'react'
import { BrandMark } from '@/components/BrandMark'
import { LanguageToggle } from '@/components/layout/LanguageMenu'
import { t } from '@/i18n'
import type { LoginConfig } from '@/lib/auth'

/** The frame of the pages that need no session: the sign-in, the setup link and the re-authentication. */
export function AuthShell({ cfg, subtitle, children, footer }: { cfg?: LoginConfig; subtitle: string; children: ReactNode; footer?: ReactNode }) {
  const name = cfg?.name || t.appName
  return (
    <div className="relative flex min-h-svh items-center justify-center bg-muted/40 p-4">
      <div className="absolute top-3 right-3">
        <LanguageToggle />
      </div>
      <div className="rb-page w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-3 text-center">
          <BrandMark logo={cfg?.logo} name={name} className="size-12 rounded-2xl" />
          <div>
            <h1 className="text-xl font-semibold tracking-tight">{name}</h1>
            <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
          </div>
        </div>
        <div className="space-y-4 rounded-2xl border bg-card p-6 shadow-xs">{children}</div>
        {footer && <p className="mt-4 text-center text-xs text-muted-foreground">{footer}</p>}
      </div>
    </div>
  )
}
