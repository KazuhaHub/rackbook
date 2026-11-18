import { Suspense, useEffect } from 'react'
import { Outlet, NavLink, useLocation } from 'react-router'
import { CalendarClock, KeyRound, LayoutDashboard, Shapes } from 'lucide-react'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from '@/components/ui/sidebar'
import { t } from '@/i18n/zh-CN'
import { BrandMark } from '@/components/BrandMark'
import { CollectionIcon } from '@/components/CollectionIcon'
import { hasExpiry } from '@/lib/ledger'
import { useMeta } from '@/providers/meta'
import { PageFallback } from '@/components/common'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { CheckBadge } from './CheckBadge'
import { HistoryAlert } from './HistoryAlert'
import { GlobalSearch } from './GlobalSearch'
import { ThemeToggle } from './ThemeToggle'
import { UserMenu } from './UserMenu'

function CloseMobileOnNavigate() {
  const { setOpenMobile } = useSidebar()
  const { pathname } = useLocation()
  useEffect(() => setOpenMobile(false), [pathname, setOpenMobile])
  return null
}

function AppSidebar() {
  const { meta } = useMeta()
  const { pathname } = useLocation()
  const productName = meta.branding?.name || t.appName

  // group collections, keeping config order (ungrouped first-seen position)
  const groups: { name: string; items: typeof meta.collections }[] = []
  for (const c of meta.collections) {
    const name = c.group || t.nav.collections
    let g = groups.find((x) => x.name === name)
    if (!g) groups.push((g = { name, items: [] }))
    g.items.push(c)
  }

  return (
    <Sidebar>
      <SidebarHeader className="gap-3 p-4 pb-2">
        <NavLink to="/" className="flex items-center gap-2.5">
          <BrandMark logo={meta.branding?.logo} name={productName} className="size-8 rounded-lg" />
          <span className="min-w-0">
            <span className="block truncate text-sm leading-tight font-semibold">
              {meta.title || t.ledgerFallbackTitle}
            </span>
            <span className="block text-xs text-muted-foreground">{productName}</span>
          </span>
        </NavLink>
        <CheckBadge className="self-start" />
      </SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton isActive={pathname === '/'} render={<NavLink to="/" />}>
                  <LayoutDashboard />
                  <span>{t.nav.dashboard}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
              {hasExpiry(meta) && (
                <SidebarMenuItem>
                  <SidebarMenuButton isActive={pathname === '/expiring'} render={<NavLink to="/expiring" />}>
                    <CalendarClock />
                    <span>{t.nav.expiring}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              )}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        {groups.map((g) => (
          <SidebarGroup key={g.name}>
            <SidebarGroupLabel className="tracking-wide">{g.name}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {g.items.map((c) => {
                  const base = `/c/${encodeURIComponent(c.name)}`
                  return (
                    <SidebarMenuItem key={c.name}>
                      <SidebarMenuButton
                        isActive={pathname === base || pathname.startsWith(base + '/')}
                        render={<NavLink to={base} />}
                      >
                        <CollectionIcon col={c} />
                        <span className="truncate">{c.title}</span>
                      </SidebarMenuButton>
                      <SidebarMenuBadge>{c.count}</SidebarMenuBadge>
                    </SidebarMenuItem>
                  )
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
        {meta.user?.canAdmin && (
          <SidebarGroup>
            <SidebarGroupLabel className="tracking-wide">{t.nav.admin}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                <SidebarMenuItem>
                  <SidebarMenuButton isActive={pathname === '/types' || pathname.startsWith('/types/')} render={<NavLink to="/types" />}>
                    <Shapes />
                    <span>{t.types.nav}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton isActive={pathname === '/admin/tokens'} render={<NavLink to="/admin/tokens" />}>
                    <KeyRound />
                    <span>{t.nav.tokens}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
      </SidebarContent>
      <SidebarFooter className="border-t p-3">
        <UserMenu />
      </SidebarFooter>
    </Sidebar>
  )
}

export function AppShell() {
  const { pathname } = useLocation()
  return (
    <SidebarProvider>
      <CloseMobileOnNavigate />
      <AppSidebar />
      <SidebarInset className="min-w-0">
        <HistoryAlert />
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur">
          <SidebarTrigger aria-label={t.nav.toggleSidebar} />
          <div className="flex min-w-0 flex-1 items-center">
            <GlobalSearch />
          </div>
          <ThemeToggle />
        </header>
        <div className="mx-auto w-full max-w-[1400px] flex-1 p-4 sm:p-8">
          <div key={pathname} className="rb-page">
            <ErrorBoundary>
              <Suspense fallback={<PageFallback />}>
                <Outlet />
              </Suspense>
            </ErrorBoundary>
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
