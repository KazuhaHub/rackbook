import { useCallback, useState } from 'react'
import { useInvalidate } from '@refinedev/core'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { t } from '@/i18n/zh-CN'
import { ApiError, errorMessage } from '@/lib/api'
import { fieldTitle, recordLabel } from '@/lib/ledger'
import type { Collection, LedgerRecord } from '@/lib/types'
import { dataProvider } from '@/providers/dataProvider'

type Entry = { baseHash: string; rec: LedgerRecord }

/**
 * Saves one field of a record from a table cell. The new value shows at once
 * (`view`), the write is a PUT with the record's hash, and a refused write
 * (409 conflict, 422 validation, anything else) puts the old value back and
 * says why in a toast. Only the queries of this collection are refreshed.
 *
 * `view(rec)` is the record to display: the optimistic or just-saved one for as long as the
 * table still holds the version the edit started from, else the table's own.
 */
export function useInlineEdit(col: Collection, onSaved?: () => void) {
  const invalidate = useInvalidate()
  const qc = useQueryClient()
  const [overlay, setOverlay] = useState<Map<string, Entry>>(new Map())
  const [saving, setSaving] = useState<Set<string>>(new Set())

  const view = useCallback(
    (rec: LedgerRecord) => {
      const o = overlay.get(rec.id)
      return o && o.baseHash === rec.hash ? o.rec : rec
    },
    [overlay],
  )

  const put = (id: string, e: Entry | null) =>
    setOverlay((m) => {
      const n = new Map(m)
      if (e) n.set(id, e)
      else n.delete(id)
      return n
    })
  const busy = (id: string, on: boolean) =>
    setSaving((s) => {
      const n = new Set(s)
      if (on) n.add(id)
      else n.delete(id)
      return n
    })

  const refresh = useCallback(() => {
    void qc.invalidateQueries({ queryKey: ['rb', 'records', col.name] })
    void qc.invalidateQueries({ queryKey: ['rb', 'history'] })
    void invalidate({ resource: col.name, invalidates: ['list', 'detail'] })
    onSaved?.()
  }, [qc, invalidate, col.name, onSaved])

  const save = useCallback(
    async (rec: LedgerRecord, field: string, value: unknown) => {
      const cur = view(rec)
      const data = { ...cur.data }
      if (value === undefined || value === null || (Array.isArray(value) && value.length === 0)) delete data[field]
      else data[field] = value
      put(rec.id, { baseHash: rec.hash, rec: { ...cur, data } })
      busy(rec.id, true)
      try {
        const res = await dataProvider.update({ resource: col.name, id: rec.id, variables: { data, hash: cur.hash } })
        const saved = res.data as unknown as LedgerRecord
        put(rec.id, { baseHash: rec.hash, rec: { id: rec.id, hash: saved.hash, data: saved.data ?? data } })
        toast.success(t.inline.saved(fieldTitle(col, field), recordLabel(col, { ...cur, data })))
        refresh()
      } catch (e) {
        put(rec.id, null)
        if (e instanceof ApiError && e.statusCode === 409) {
          toast.error(t.inline.conflict)
          refresh() // fetch the version somebody else saved
        } else {
          toast.error(t.inline.failed(fieldTitle(col, field), errorMessage(e)))
        }
      } finally {
        busy(rec.id, false)
      }
    },
    [col, view, refresh],
  )

  return { view, save, isSaving: (id: string) => saving.has(id) }
}
