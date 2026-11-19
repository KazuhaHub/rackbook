import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Link } from 'react-router'
import { TriangleAlert } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { t } from '@/i18n/zh-CN'
import { isChunkLoadError, reloadForStaleChunk } from '@/lib/staleChunk'

type State = { error: Error | null }

/** Keeps a render error in one page from blanking the whole console. */
export class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }
  static getDerivedStateFromError(error: Error): State {
    return { error }
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(error, info.componentStack)
    // Normally retryImport already reloaded; this catches any other stale chunk.
    if (isChunkLoadError(error)) reloadForStaleChunk()
  }
  render() {
    if (!this.state.error) return this.props.children
    if (isChunkLoadError(this.state.error)) {
      return (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-16 text-center">
          <TriangleAlert className="size-10 text-muted-foreground" />
          <div className="text-lg font-medium">{t.errors.updatedTitle}</div>
          <p className="max-w-md text-sm text-muted-foreground">{t.errors.updatedBody}</p>
          <Button onClick={() => window.location.reload()}>{t.errors.refresh}</Button>
        </div>
      )
    }
    return (
      <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed px-6 py-16 text-center">
        <TriangleAlert className="size-10 text-muted-foreground" />
        <div className="text-lg font-medium">{t.errors.crashTitle}</div>
        <p className="max-w-md text-sm text-muted-foreground">{t.errors.crashBody}</p>
        <p className="max-w-lg font-mono text-xs break-words text-muted-foreground">{this.state.error.message}</p>
        <div className="flex gap-2">
          <Button onClick={() => this.setState({ error: null })}>{t.errors.retry}</Button>
          <Button variant="outline" render={<Link to="/" onClick={() => this.setState({ error: null })} />}>
            {t.notFound.back}
          </Button>
        </div>
      </div>
    )
  }
}
