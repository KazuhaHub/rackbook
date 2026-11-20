import { useState } from 'react'
import { ChevronDown, ListFilter } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { EnumIcon } from '@/components/EnumIcon'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'

export type FacetOption = { value: string; label: string; count: number; icon?: string }

export function FacetFilter({
  label,
  options,
  selected,
  onChange,
}: {
  label: string
  options: FacetOption[]
  selected: string[]
  onChange: (next: string[]) => void
}) {
  const [q, setQ] = useState('')
  const shown = q ? options.filter((o) => (o.label + ' ' + o.value).toLowerCase().includes(q.toLowerCase())) : options
  const toggle = (v: string) => onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v])
  return (
    <Popover>
      <PopoverTrigger render={<Button variant="outline" size="sm" className={selected.length ? 'border-primary/50' : ''} />}>
        <ListFilter />
        {label}
        {selected.length > 0 && (
          <span className="rounded-full bg-primary px-1.5 text-[10px] leading-4 text-primary-foreground">{selected.length}</span>
        )}
        <ChevronDown className="opacity-60" />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 gap-2 p-2">
        {options.length > 8 && (
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="…" className="h-8" />
        )}
        <div className="max-h-64 overflow-auto">
          {shown.map((o) => (
            <label
              key={o.value}
              className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-muted"
            >
              <Checkbox checked={selected.includes(o.value)} onCheckedChange={() => toggle(o.value)} />
              <EnumIcon name={o.icon} />
              <span className="min-w-0 flex-1 truncate">{o.label}</span>
              <span className="text-xs text-muted-foreground tabular-nums">{o.count}</span>
            </label>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  )
}
