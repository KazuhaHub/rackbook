import { t } from '../i18n/index.ts'
import type { ActivityItem } from './activity.ts'

const detailValue = (it: ActivityItem, key: string) => it.detail?.find((d) => d.startsWith(key))?.slice(key.length)

/** An audit event as a sentence without its subject (the row shows who). */
export function eventSentence(it: ActivityItem): string {
  const e = t.activity.events
  const role = (it.role && t.auth.role[it.role]) || it.role || ''
  const method = (it.method && t.auth.method[it.method]) || it.method || ''
  switch (it.kind) {
    case 'login': {
      const notes = [it.groups === 'overage' ? e.overage.groups : '', it.app_roles === 'overage' ? e.overage.appRoles : ''].filter(Boolean)
      return e.login(role, method) + (notes.length ? `${t.common.colon}${notes.join(t.common.clauseSep)}` : '')
    }
    case 'logout':
      return e.logout
    case 'login_refused':
      return e.loginRefused(e.reasons[it.reason ?? ''] ?? it.reason ?? '')
    case 'role_changed': {
      const label = (r?: string) => (r && t.auth.role[r]) || r || ''
      const auditor = it.auditor_from === it.auditor_to ? '' : it.auditor_to ? 'on' : 'off'
      return e.roleChanged(label(it.from), label(it.to), auditor, e.causes[it.cause ?? ''] ?? it.cause ?? '')
    }
    case 'write_refused':
      return e.writeRefused(it.area === 'infra' ? t.activity.filters.area.infra : t.activity.filters.area.ledger, e.codes[it.code ?? ''] ?? it.code ?? '')
    case 'secret_revealed':
      return e.secretRevealed(it.host ?? '')
    case 'secret_reveal_refused':
      return e.secretRevealRefused(it.host ?? '')
    case 'reencrypted':
      return e.reencrypted(it.host ?? '')
    case 'accept_remote':
      return e.acceptRemote
    case 'history_rewritten':
      return e.historyRewritten
    case 'chain_problem':
      return e.chainProblem(it.code ?? '', detailValue(it, 'seq=') ?? '')
    case 'chain_problem_ack':
      return e.chainProblemAck(detailValue(it, 'through:') ?? '')
    default:
      return e.other(it.kind, it.code ?? it.reason ?? '')
  }
}
