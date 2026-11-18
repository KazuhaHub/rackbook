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

/** First match wins; matched against the collection name and title, lower-cased. */
const keywords: [RegExp, LucideIcon][] = [
  [/todo|待办|任务|事项/, ListTodo],
  [/\b(rules?|specs?)\b|规范|规则/, ListChecks],
  [/\bports?\b|端口/, Hash],
  [/range|cidr|subnet|网段|地址池|地址段/, Waypoints],
  [/site|location|room|站点|机房|位置|地点/, MapPin],
  [/\b(services?|apps?)\b|服务|应用/, Plug],
  [/address|addr|\bip|地址/, Network],
  [/domain|dns|域名/, Globe],
  [/device|host|server|machine|node|设备|主机|服务器|机器|节点/, Server],
  [/\b(vms?|docker|containers?)\b|虚拟|容器/, Boxes],
  [/storage|disk|volume|存储|磁盘/, HardDrive],
  [/backup|备份/, Archive],
  [/cert|证书/, ShieldCheck],
  [/\b(secrets?|credentials?|keys?)\b|密钥|凭据/, KeyRound],
  [/user|account|member|账号|用户|成员/, Users],
  [/contact|联系/, Contact],
  [/\b(cables?|links?)\b|线缆|链路/, Cable],
]

export function collectionIcon(c: Pick<Collection, 'name' | 'title'> & { icon?: string }): LucideIcon {
  const named = c.icon ? registry[c.icon.toLowerCase().replace(/[^a-z]/g, '')] : undefined
  if (named) return named
  const hay = `${c.name} ${c.title}`.toLowerCase()
  for (const [re, icon] of keywords) if (re.test(hay)) return icon
  return Database
}
