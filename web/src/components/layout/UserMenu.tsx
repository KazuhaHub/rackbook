import { Link } from 'react-router'
import { ChevronsUpDown, Lock, LogOut, UserRound, Users } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { t } from '@/i18n'
import { hasSession, logout } from '@/lib/auth'
import { useMeta } from '@/providers/meta'
import { LanguageSubmenu, LanguageToggle } from './LanguageMenu'

export function roleLabel(role?: string) {
  return role ? (t.auth.role[role] ?? role) : ''
}

/** Sidebar footer: who is logged in, with the account page and logout. */
export function UserMenu() {
  const { meta } = useMeta()
  const u = meta.user
  const label = u?.name || u?.email || u?.id || t.user.anonymous
  const detail = u?.email || u?.id
  const session = hasSession(u?.authMethod)

  const identity = (
    <>
      <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/10 text-sm font-semibold text-primary uppercase">
        {(label.trim()[0] ?? '?').toString()}
      </span>
      <span className="min-w-0 flex-1 text-left">
        <span className="block truncate text-sm leading-tight font-medium">{label}</span>
        <span className="block truncate text-xs text-muted-foreground">{u?.role ? roleLabel(u.role) : detail}</span>
      </span>
    </>
  )

  if (!session) {
    // cloudflare-access / none: there is no session to end, so just show who it is
    return (
      <div className="flex items-center gap-2 text-xs">
        <span className="min-w-0 flex-1 truncate text-muted-foreground" title={u?.email}>
          {u?.email || u?.name || t.user.anonymous}
        </span>
        <LanguageToggle user={u} />
        {!u?.canEdit && (
          <Badge variant="secondary" title={t.user.readOnlyHint}>
            <Lock />
            {t.user.readOnly}
          </Badge>
        )}
      </div>
    )
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        aria-label={t.auth.menu.open}
        className="flex w-full items-center gap-2.5 rounded-lg p-1.5 text-left outline-none transition-colors hover:bg-sidebar-accent focus-visible:ring-3 focus-visible:ring-ring/50 aria-expanded:bg-sidebar-accent"
      >
        {identity}
        <ChevronsUpDown className="size-4 shrink-0 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" side="top" className="w-60">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="space-y-0.5">
            <span className="block truncate text-sm font-medium text-foreground">{label}</span>
            {detail && detail !== label && <span className="block truncate text-xs font-normal">{detail}</span>}
          </DropdownMenuLabel>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem render={<Link to="/account" />}>
          <UserRound /> {t.auth.menu.account}
        </DropdownMenuItem>
        {u?.canAdmin && (
          <DropdownMenuItem render={<Link to="/admin/users" />}>
            <Users /> {t.auth.menu.users}
          </DropdownMenuItem>
        )}
        <LanguageSubmenu user={u} />
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onClick={() => void logout()}>
          <LogOut /> {t.auth.menu.logout}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
