import { lazy } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router'
import { Refine } from '@refinedev/core'
import routerProvider, { DocumentTitleHandler, UnsavedChangesNotifier } from '@refinedev/react-router'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from 'next-themes'
import { Toaster } from '@/components/ui/sonner'
import { TooltipProvider } from '@/components/ui/tooltip'
import { NotFound, PageFallback, Unreachable } from '@/components/common'
import { AppShell } from '@/components/layout/AppShell'
import { t } from '@/i18n/zh-CN'
import { dataProvider } from '@/providers/dataProvider'
import { MetaProvider, useMeta } from '@/providers/meta'

// Route-level code splitting: the table and form stacks are the heavy parts.
const Dashboard = lazy(() => import('@/pages/Dashboard'))
const CollectionList = lazy(() => import('@/pages/CollectionList'))
const RecordShow = lazy(() => import('@/pages/RecordShow'))
const RecordFormPage = lazy(() => import('@/pages/RecordFormPage'))
const Problems = lazy(() => import('@/pages/Problems'))

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
        meta: { label: c.title },
      }))}
      options={{
        syncWithLocation: false,
        warnWhenUnsavedChanges: false,
        disableTelemetry: true,
        title: { text: meta.title || t.appName },
        reactQuery: { clientConfig: queryClient },
      }}
    >
      <Routes>
        <Route
          element={<AppShell />}
        >
          <Route index element={<Dashboard />} />
          <Route path="c/:collection" element={<CollectionList />} />
          <Route path="c/:collection/-/new" element={<RecordFormPage mode="create" />} />
          <Route path="c/:collection/:id" element={<RecordShow />} />
          <Route path="c/:collection/:id/edit" element={<RecordFormPage mode="edit" />} />
          <Route path="check" element={<Problems />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
      <UnsavedChangesNotifier />
      <DocumentTitleHandler handler={({ resource, action }) => titleFor(meta.title, resource?.meta?.label, action)} />
    </Refine>
  )
}

function titleFor(ledger: string, label: unknown, action?: string) {
  const base = ledger || t.appName
  if (!label) return base
  const verb = action === 'create' ? '新增 · ' : action === 'edit' ? '编辑 · ' : ''
  return `${verb}${String(label)} · ${base}`
}

export default function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delay={200}>
          <BrowserRouter>
            <MetaProvider
              loading={<div className="p-8"><PageFallback /></div>}
              failed={(e, retry) => <Unreachable error={e} onRetry={retry} />}
            >
              <RefineApp />
            </MetaProvider>
          </BrowserRouter>
          <Toaster richColors position="bottom-right" />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}
