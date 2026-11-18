import type { DataProvider } from '@refinedev/core'
import { API_BASE, apiFetch } from '@/lib/api'
import type { LedgerRecord, RecordWithBackrefs } from '@/lib/types'

const seg = (id: unknown) => encodeURIComponent(String(id))

/**
 * Refine data provider for the Rackbook HTTP API (docs/api.md).
 * Rows keep the server shape: { id, hash, data }.
 */
export const dataProvider: DataProvider = {
  getApiUrl: () => API_BASE,

  // The server returns the whole collection; filtering and sorting happen in the table.
  getList: async ({ resource }) => {
    const res = await apiFetch<{ records: LedgerRecord[] }>(`/c/${seg(resource)}`)
    return { data: res.records as any[], total: res.records.length }
  },

  getOne: async ({ resource, id }) => {
    const res = await apiFetch<RecordWithBackrefs>(`/c/${seg(resource)}/${seg(id)}`)
    return { data: res as any }
  },

  // variables: { data }
  create: async ({ resource, variables }) => {
    const res = await apiFetch<LedgerRecord & { commit: string }>(`/c/${seg(resource)}`, {
      method: 'POST',
      body: JSON.stringify({ data: (variables as any).data }),
    })
    return { data: res as any }
  },

  // variables: { data, hash }
  update: async ({ resource, id, variables }) => {
    const v = variables as { data: unknown; hash: string }
    const res = await apiFetch<LedgerRecord & { commit: string }>(`/c/${seg(resource)}/${seg(id)}`, {
      method: 'PUT',
      body: JSON.stringify({ data: v.data, hash: v.hash }),
    })
    return { data: res as any }
  },

  // variables: { hash }
  deleteOne: async ({ resource, id, variables }) => {
    const hash = (variables as { hash?: string } | undefined)?.hash ?? ''
    const res = await apiFetch<{ commit: string }>(
      `/c/${seg(resource)}/${seg(id)}?hash=${encodeURIComponent(hash)}`,
      { method: 'DELETE' },
    )
    return { data: res as any }
  },

  // /meta, /check and /history are not CRUD: reached through `custom`.
  // `url` is relative to /api, `query` becomes the query string.
  custom: async ({ url, method, payload, query }) => {
    const qs = new URLSearchParams()
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined && v !== '') qs.set(k, String(v))
    const path = url.replace(/^\/api/, '') + (qs.size ? `?${qs}` : '')
    const data = await apiFetch<any>(path, {
      method: (method ?? 'get').toUpperCase(),
      body: payload ? JSON.stringify(payload) : undefined,
    })
    return { data }
  },
}
