import { Suspense, useEffect } from 'react'
import { Outlet, NavLink, useLocation } from 'react-router'
import { CalendarClock, FileClock, KeyRound, LayoutDashboard, List, PlugZap, Puzzle, Layers, Server, Shapes, ShieldCheck } from 'lucide-react'
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
import { t } from '@/i18n'
import { BrandMark } from '@/components/BrandMark'
import { CollectionIcon } from '@/components/CollectionIcon'
import { hasExpiry } from '@/lib/ledger'
import { collectionGroup, collectionTitle, ledgerTitle } from '@/lib/labels'
import { failedCount } from '@/lib/modules'
import { useModules } from '@/lib/modulesApi'
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
  // a red count beside 模块 when a module's last run failed (administrators only)
  const modulesQ = useModules(!!meta.user?.canAdmin && (meta.modules?.length ?? 0) > 0, 60_000)
  const failedModules = failedCount(modulesQ.data?.modules ?? [])

  // group collections, keeping config order (ungrouped first-seen position)
  // grouped by the standard group name, so a collection without a translation stays with its siblings;
  // the group shows the translated name when any member has one
  const groups: { key: string; name: string; items: typeof meta.collections }[] = []
  for (const c of meta.collections) {
    const key = c.group || ''
    let g = groups.find((x) => x.key === key)
    if (!g) groups.push((g = { key, name: '', items: [] }))
    g.items.push(c)
  }
  for (const g of groups) {
    // the ungrouped bucket keeps its own name: a translation without a standard group names no group
    g.name = g.key ? g.items.map((c) => collectionGroup(c) ?? '').find((n) => n && n !== g.key) || g.key : t.nav.collections
  }

  return (
    <Sidebar>
      <SidebarHeader className="gap-3 p-4 pb-2">
        <NavLink to="/" className="flex items-center gap-2.5">
          <BrandMark logo={meta.branding?.logo} name={productName} className="size-8 rounded-lg" />
          <span className="min-w-0">
            <span className="block truncate text-sm leading-tight font-semibold">
              {ledgerTitle(meta) || t.ledgerFallbackTitle}
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
          <SidebarGroup key={g.key}>
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
                        <span className="truncate">{collectionTitle(c)}</span>
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
                  <SidebarMenuButton isActive={pathname === '/modules' || pathname.startsWith('/modules/')} render={<NavLink to="/modules" />}>
                    <Puzzle />
                    <span>{t.nav.modules}</span>
                  </SidebarMenuButton>
                  {failedModules > 0 && (
                    <SidebarMenuBadge className="bg-destructive text-white!" title={t.modules.failedBanner(failedModules)}>
                      {failedModules}
                    </SidebarMenuBadge>
                  )}
                </SidebarMenuItem>
                <SidebarMenuItem>
                  <SidebarMenuButton isActive={pathname === '/admin/tokens'} render={<NavLink to="/admin/tokens" />}>
                    <KeyRound />
                    <span>{t.nav.tokens}</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
                {meta.oauthServer && (
                  <SidebarMenuItem>
                    <SidebarMenuButton isActive={pathname === '/admin/grants'} render={<NavLink to="/admin/grants" />}>
                      <PlugZap />
                      <span>{t.nav.grants}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                )}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
        {meta.user?.canInfra && (
          <SidebarGroup>
            <SidebarGroupLabel className="tracking-wide">{t.infra.nav}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {[
                  { to: '/infra', icon: <Server />, label: t.infra.tabs.hosts, active: pathname === '/infra' || pathname.startsWith('/infra/hosts/') },
                  ...(meta.user?.canInfraWrite ? [{ to: '/infra/groups', icon: <Layers />, label: t.infra.tabs.groups, active: pathname === '/infra/groups' }] : []),
                  { to: '/infra/certs', icon: <ShieldCheck />, label: t.infra.tabs.certs, active: pathname === '/infra/certs' },
                  { to: '/infra/iplists', icon: <List />, label: t.infra.tabs.iplists, active: pathname === '/infra/iplists' },
                  { to: '/infra/commits', icon: <FileClock />, label: t.infra.tabs.commits, active: pathname === '/infra/commits' },
                ].map((i) => (
                  <SidebarMenuItem key={i.to}>
                    <SidebarMenuButton isActive={i.active} render={<NavLink to={i.to} />}>
                      {i.icon}
                      <span>{i.label}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
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
