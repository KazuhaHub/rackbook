import { t } from '../i18n/index.ts'
import type { ActivityItem } from './activity.ts'

const detailValue = (it: ActivityItem, key: string) => it.detail?.find((d) => d.startsWith(key))?.slice(key.length)

/** What an event says about /infra: how the person was an administrator or auditor, and what an overage cost them. */
function infraNotes(it: ActivityItem): string[] {
  const e = t.activity.events.infra
  const lost = (it.infra_overage ?? '').split(',').filter(Boolean).map((k) => e.overage[k] ?? k)
  return [
    it.infra_via && e.admin[it.infra_via] ? e.admin[it.infra_via] : '',
    it.infra_auditor_via && e.auditor[it.infra_auditor_via] ? e.auditor[it.infra_auditor_via] : '',
    ...lost,
  ].filter(Boolean)
}

/** A sentence for an infra event, with how the person was an administrator when that was not by name. */
function withInfra(s: string, it: ActivityItem): string {
  const via = it.infra_via && it.infra_via !== 'identity' ? t.activity.events.infra.admin[it.infra_via] : ''
  return via ? `${s}${t.common.colon}${via}` : s
}

/** An audit event as a sentence without its subject (the row shows who); an event about another account says which. */
export function eventSentence(it: ActivityItem): string {
  const s = baseSentence(it)
  return it.target ? `${s}${t.common.clauseSep}${t.activity.events.onAccount(it.target)}` : s
}

function baseSentence(it: ActivityItem): string {
  const e = t.activity.events
  const role = (it.role && t.auth.role[it.role]) || it.role || ''
  const method = (it.method && t.auth.method[it.method]) || it.method || ''
  switch (it.kind) {
    case 'login': {
      const notes = [it.groups === 'overage' ? e.overage.groups : '', it.app_roles === 'overage' ? e.overage.appRoles : ''].filter(Boolean)
      notes.push(...infraNotes(it))
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
      return withInfra(e.secretRevealed(it.host ?? ''), it)
    case 'secret_reveal_refused':
      return withInfra(e.secretRevealRefused(it.host ?? ''), it)
    case 'reencrypted':
      return withInfra(e.reencrypted(it.host ?? ''), it)
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
