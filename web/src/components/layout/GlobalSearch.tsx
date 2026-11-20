import { useDeferredValue, useEffect, useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { useNavigate } from 'react-router'
import { Button } from '@/components/ui/button'
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from '@/components/ui/command'
import { t } from '@/i18n'
import { useAllRecords } from '@/lib/hooks'
import { fieldTitle, recordHref, recordLabel, str } from '@/lib/ledger'
import { useMeta } from '@/providers/meta'

const PER_GROUP = 8

export function GlobalSearch() {
  const { meta } = useMeta()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const dq = useDeferredValue(q.trim().toLowerCase())
  // All collections are small; load them the first time search is opened.
  const results = useAllRecords(
    meta.collections.map((c) => c.name),
    open,
  )
  const stamp = results.map((r) => r.dataUpdatedAt).join(',')

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen((o) => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const groups = useMemo(() => {
    if (!dq) return []
    return meta.collections
      .map((c, i) => {
        const hits = (results[i]?.data ?? [])
          .map((r) => {
            const matchedField = Object.entries(r.data).find(([, v]) => str(v).toLowerCase().includes(dq))
            return matchedField ? { r, field: matchedField[0], value: str(matchedField[1]) } : null
          })
          .filter((x) => x !== null)
        return { c, hits }
      })
      .filter((g) => g.hits.length)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq, stamp, meta])

  const go = (href: string) => {
    setOpen(false)
    setQ('')
    navigate(href)
  }

  return (
    <>
      <Button
        variant="outline"
        className="h-8 w-full max-w-sm justify-start gap-2 text-muted-foreground"
        onClick={() => setOpen(true)}
      >
        <Search className="size-4" />
        <span className="truncate">{t.nav.search}</span>
        <kbd className="ml-auto hidden rounded border bg-muted px-1.5 font-mono text-[10px] sm:inline">⌘K</kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={setOpen} title={t.nav.search} description={t.nav.searchHint} className="sm:max-w-xl">
        <Command shouldFilter={false}>
          <CommandInput value={q} onValueChange={setQ} placeholder={t.nav.searchPlaceholder} />
          <CommandList className="max-h-[60vh]">
            {!dq ? (
              <div className="py-8 text-center text-sm text-muted-foreground">{t.nav.searchHint}</div>
            ) : (
              <>
                <CommandEmpty>{t.nav.searchEmpty}</CommandEmpty>
                {groups.map(({ c, hits }) => (
                  <CommandGroup key={c.name} heading={`${c.title} · ${hits.length}`}>
                    {hits.slice(0, PER_GROUP).map(({ r, field, value }) => (
                      <CommandItem
                        key={r.id}
                        value={`${c.name}/${r.id}`}
                        onSelect={() => go(recordHref(c.name, r.id))}
                      >
                        <div className="flex min-w-0 flex-col">
                          <span className="truncate font-medium">{recordLabel(c, r)}</span>
                          <span className="truncate text-xs text-muted-foreground">
                            {fieldTitle(c, field)}{t.common.colon}<span className="font-mono">{value}</span>
                          </span>
                        </div>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                ))}
              </>
            )}
          </CommandList>
        </Command>
      </CommandDialog>
    </>
  )
}
