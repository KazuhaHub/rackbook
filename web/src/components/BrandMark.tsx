import { BookMarked } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * The product mark: the custom logo (served at /branding/logo, shown only
 * through <img>) or the default Rackbook mark.
 */
export function BrandMark({ logo, name, className }: { logo?: boolean; name: string; className: string }) {
  if (logo) {
    return <img src="/branding/logo" alt={name} className={cn('shrink-0 object-contain', className)} />
  }
  return (
    <span className={cn('flex shrink-0 items-center justify-center bg-primary text-primary-foreground shadow-sm', className)} aria-hidden>
      <BookMarked className="size-1/2" />
    </span>
  )
}
