import {
  Archive,
  Boxes,
  Cable,
  Cloud,
  Calendar,
  Contact,
  Cpu,
  Folder,
  Laptop,
  Router,
  Tag,
  Wrench,
  Database,
  Globe,
  Hash,
  HardDrive,
  KeyRound,
  ListChecks,
  ListTodo,
  MapPin,
  Network,
  Plug,
  ShieldCheck,
  Server,
  Users,
  Waypoints,
  type LucideIcon,
} from 'lucide-react'
import { ICON_KEYWORDS } from '../i18n/icon-keywords.ts'
import type { Collection } from './types'

/** Icons a ledger can name through an optional `icon` in /api/meta (lucide names, any case or dashes). */
const registry: Record<string, LucideIcon> = {
  archive: Archive,
  boxes: Boxes,
  cable: Cable,
  cloud: Cloud,
  contact: Contact,
  database: Database,
  globe: Globe,
  hash: Hash,
  harddrive: HardDrive,
  keyround: KeyRound,
  listchecks: ListChecks,
  listtodo: ListTodo,
  mappin: MapPin,
  network: Network,
  plug: Plug,
  shieldcheck: ShieldCheck,
  server: Server,
  users: Users,
  waypoints: Waypoints,
  calendar: Calendar,
  cpu: Cpu,
  folder: Folder,
  laptop: Laptop,
  router: Router,
  tag: Tag,
  wrench: Wrench,
}

/** The icons the data type editor offers, as the names written to rackbook.yml. */
export const iconChoices: { name: string; Icon: LucideIcon }[] = [
  ['server', Server], ['laptop', Laptop], ['router', Router], ['cpu', Cpu], ['hard-drive', HardDrive], ['boxes', Boxes],
  ['database', Database], ['cloud', Cloud], ['network', Network], ['waypoints', Waypoints], ['globe', Globe], ['plug', Plug],
  ['cable', Cable], ['hash', Hash], ['map-pin', MapPin], ['users', Users], ['contact', Contact], ['key-round', KeyRound],
  ['shield-check', ShieldCheck], ['list-todo', ListTodo], ['list-checks', ListChecks], ['archive', Archive], ['folder', Folder],
  ['tag', Tag], ['calendar', Calendar], ['wrench', Wrench],
].map(([name, Icon]) => ({ name: name as string, Icon: Icon as LucideIcon }))

const byName = new Map(iconChoices.map((c) => [c.name, c.Icon]))

/** First match wins; matched against the collection name and title, lower-cased, in every language at once. */
const keywords: [RegExp, LucideIcon][] = ICON_KEYWORDS.map((k) => {
  const words = [...new Set([...k.zhCN, ...k.zhTW])].map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
  return [new RegExp([...k.en, ...words].join('|')), byName.get(k.icon)!]
})

export function collectionIcon(c: Pick<Collection, 'name' | 'title'> & { icon?: string }): LucideIcon {
  const named = c.icon ? registry[c.icon.toLowerCase().replace(/[^a-z]/g, '')] : undefined
  if (named) return named
  const hay = `${c.name} ${c.title}`.toLowerCase()
  for (const [re, icon] of keywords) if (re.test(hay)) return icon
  return Database
}
