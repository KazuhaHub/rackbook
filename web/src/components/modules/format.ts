import { t } from '@/i18n'
import { formatDateTime } from '@/i18n/format'
import { countParts, type ModuleRun, type ModuleType } from '@/lib/modules'

export function when(s?: string | null, timeZone?: string) {
  if (!s) return '—'
  return formatDateTime(s, timeZone)
}

export function took(r: ModuleRun) {
  const sec = Math.max(0, Math.round((new Date(r.finished).getTime() - new Date(r.started).getTime()) / 1000))
  return sec < 90 ? t.modules.seconds(sec) : t.modules.minutes(Math.round(sec / 60))
}

/** "新增 2 · 更新 1", or "没有变化" when nothing was done. */
export function doneText(r: ModuleRun, type: ModuleType) {
  const parts = countParts(r.counts, type).filter((p) => p.n > 0)
  return parts.length ? parts.map((p) => `${t.modules.counts[p.key]} ${p.n}`).join(' · ') : t.modules.nothingDone
}
