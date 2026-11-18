import { cn } from 'cn'

/** A unified diff, colour-coded by line. */
export function DiffView({ diff, className }: { diff: string; className?: string }) {
  const lines = diff.replace(/\n$/, '').split('\n')
  return (
    <pre className={cn('overflow-x-auto rounded-lg border bg-muted/30 py-2 font-mono text-xs leading-relaxed', className)}>
      {lines.map((l, i) => {
        const kind = l.startsWith('+++') || l.startsWith('---') ? 'meta' : l.startsWith('@@') ? 'hunk' : l[0]
        return (
          <div
            key={i}
            className={cn(
              'px-3 whitespace-pre',
              kind === '+' && 'bg-green-500/10 text-green-700 dark:text-green-300',
              kind === '-' && 'bg-red-500/10 text-red-700 dark:text-red-300',
              kind === 'hunk' && 'text-brand',
              kind === 'meta' && 'text-muted-foreground',
            )}
          >
            {l || ' '}
          </div>
        )
      })}
    </pre>
  )
}
