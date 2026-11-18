import { useState } from 'react'
import { X } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Input } from '@/components/ui/input'

/** A list of short strings: type a value and press Enter (or comma); click a chip's × to remove it. */
export function TagInput({
  value,
  onChange,
  placeholder,
  mono,
}: {
  value: string[]
  onChange: (v: string[]) => void
  placeholder?: string
  mono?: boolean
}) {
  const [text, setText] = useState('')
  const add = () => {
    const v = text.trim()
    if (v && !value.includes(v)) onChange([...value, v])
    setText('')
  }
  return (
    <div className="space-y-2">
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {value.map((v) => (
            <Badge key={v} variant="secondary" className={mono ? 'font-mono' : ''}>
              {v}
              <button
                type="button"
                className="-mr-1 rounded-full p-0.5 hover:bg-foreground/10"
                aria-label={`移除 ${v}`}
                onClick={() => onChange(value.filter((x) => x !== v))}
              >
                <X />
              </button>
            </Badge>
          ))}
        </div>
      )}
      <Input
        value={text}
        placeholder={placeholder}
        onChange={(e) => setText(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault()
            add()
          } else if (e.key === 'Backspace' && !text && value.length) {
            onChange(value.slice(0, -1))
          }
        }}
        onBlur={add}
      />
    </div>
  )
}
