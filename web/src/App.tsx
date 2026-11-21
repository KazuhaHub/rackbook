import { lazy, Suspense } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router'
import { Refine } from '@refinedev/core'
import routerProvider, { DocumentTitleHandler, UnsavedChangesNotifier } from '@refinedev/react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from 'next-themes'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { NotFound, PageFallback, Unreachable } from '@/components/common'
import { AppShell } from '@/components/layout/AppShell'
import { LocaleBoundary, LocaleSync } from '@/components/layout/LanguageMenu'
import { ErrorBoundary } from '@/components/ErrorBoundary'
import { t } from '@/i18n'
import { dataProvider } from '@/providers/dataProvider'
import { MetaProvider, useMeta } from '@/providers/meta'
import { collectionTitle, ledgerTitle } from '@/lib/labels'
import { retryImport } from '@/lib/staleChunk'

// Route-level code splitting: the table and form stacks are the heavy parts.
const Dashboard = lazy(retryImport(() => import('@/pages/Dashboard')))
const CollectionList = lazy(retryImport(() => import('@/pages/CollectionList')))
const RecordShow = lazy(retryImport(() => import('@/pages/RecordShow')))
const RecordFormPage = lazy(retryImport(() => import('@/pages/RecordFormPage')))
const Problems = lazy(retryImport(() => import('@/pages/Problems')))
const Expiring = lazy(retryImport(() => import('@/pages/Expiring')))
const Account = lazy(retryImport(() => import('@/pages/Account')))
const Users = lazy(retryImport(() => import('@/pages/Users')))
const Login = lazy(retryImport(() => import('@/pages/Login')))
const Tokens = lazy(retryImport(() => import('@/pages/Tokens')))
const AdminGrants = lazy(retryImport(() => import('@/pages/AdminGrants')))
// the page the built-in authorization server sends the person to
const Consent = lazy(retryImport(() => import('@/pages/Consent')))
// modules panel (admin)
const Modules = lazy(retryImport(() => import('@/pages/Modules')))
const ModuleDetail = lazy(retryImport(() => import('@/pages/ModuleDetail')))
// infra: read-only view of the Ansible + SOPS repository and the hub status (infra administrators)
const InfraHosts = lazy(retryImport(() => import('@/pages/InfraHosts')))
const InfraHost = lazy(retryImport(() => import('@/pages/InfraHost')))
const InfraCerts = lazy(retryImport(() => import('@/pages/InfraCerts')))
const InfraIPLists = lazy(retryImport(() => import('@/pages/InfraIPLists')))
const InfraCommits = lazy(retryImport(() => import('@/pages/InfraCommits')))
const InfraHostEdit = lazy(retryImport(() => import('@/pages/InfraHostEdit')))
const InfraGroups = lazy(retryImport(() => import('@/pages/InfraGroups')))
// data types (admin)
const Types = lazy(retryImport(() => import('@/pages/Types')))
const TypeEditor = lazy(retryImport(() => import('@/pages/TypeEditor')))

const queryClient = new QueryClient({
  defaultOptions: { queries: { refetchOnWindowFocus: false } },
})

function RefineApp() {
  const { meta } = useMeta()
  return (
    <Refine
      dataProvider={dataProvider}
      routerProvider={routerProvider}
      resources={meta.collections.map((c) => ({
        name: c.name,
        list: `/c/${c.name}`,
        create: `/c/${c.name}/-/new`,
        show: `/c/${c.name}/:id`,
        edit: `/c/${c.name}/:id/edit`,
        meta: { label: collectionTitle(c) },
      }))}
      options={{
        syncWithLocation: false,
        warnWhenUnsavedChanges: false,
        disableTelemetry: true,
        title: { text: ledgerTitle(meta) || meta.branding?.name || t.appName },
        reactQuery: { clientConfig: queryClient },
      }}
    >
      <LocaleSync meta={meta} />
      <Routes>
        <Route
          path="oauth/consent"
          element={
            <ErrorBoundary>
              <Suspense fallback={<div className="p-8"><PageFallback /></div>}>
                <Consent />
              </Suspense>
            </ErrorBoundary>
          }
        />
        <Route
          element={<AppShell />}
        >
          <Route index element={<Dashboard />} />
          <Route path="c/:collection" element={<CollectionList />} />
          <Route path="c/:collection/-/new" element={<RecordFormPage mode="create" />} />
          <Route path="c/:collection/:id" element={<RecordShow />} />
          <Route path="c/:collection/:id/edit" element={<RecordFormPage mode="edit" />} />
          <Route path="check" element={<Problems />} />
          <Route path="expiring" element={<Expiring />} />
          <Route path="account" element={<Account />} />
          <Route path="admin/users" element={<Users />} />
          <Route path="admin/tokens" element={<Tokens />} />
          <Route path="admin/grants" element={<AdminGrants />} />
          <Route path="modules" element={<Modules />} />
          <Route path="modules/:name" element={<ModuleDetail />} />
          <Route path="infra" element={<InfraHosts />} />
          <Route path="infra/hosts/:name" element={<InfraHost />} />
          <Route path="infra/certs" element={<InfraCerts />} />
          <Route path="infra/iplists" element={<InfraIPLists />} />
          <Route path="infra/hosts/:name/edit" element={<InfraHostEdit />} />
          <Route path="infra/groups" element={<InfraGroups />} />
          <Route path="infra/commits" element={<InfraCommits />} />
          <Route path="types" element={<Types />} />
          <Route path="types/-/new" element={<TypeEditor mode="create" />} />
          <Route path="types/:name" element={<TypeEditor mode="edit" />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
      <UnsavedChangesNotifier />
      <DocumentTitleHandler handler={({ resource, action }) => titleFor(ledgerTitle(meta) || meta.branding?.name || '', resource?.meta?.label, action)} />
    </Refine>
  )
}

function titleFor(ledger: string, label: unknown, action?: string) {
  const base = ledger || t.appName
  if (!label) return base
  const d = t.form.docTitle
  return (action === 'create' ? d.create : action === 'edit' ? d.edit : d.other)(String(label), base)
}

export default function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delay={200}>
          <LocaleBoundary>
            <BrowserRouter>
              <Routes>
                {/* the login page needs no session, so it lives outside MetaProvider */}
                <Route
                  path="/auth/login"
                  element={
                    <ErrorBoundary>
                      <Suspense fallback={<div className="p-8"><PageFallback /></div>}>
                        <Login />
                      </Suspense>
                    </ErrorBoundary>
                  }
                />
                <Route
                  path="*"
                  element={
                    <MetaProvider
                      loading={<div className="p-8"><PageFallback /></div>}
                      failed={(e, retry) => <Unreachable error={e} onRetry={retry} />}
                    >
                      <RefineApp />
                    </MetaProvider>
                  }
                />
              </Routes>
            </BrowserRouter>
          </LocaleBoundary>
          <Toaster richColors position="bottom-right" />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
