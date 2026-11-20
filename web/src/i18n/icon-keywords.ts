// Keywords that pick a collection's icon from its name and title.
//
// A collection's title is configured text in whatever language its owner
// writes, independent of the console's UI language, so the keywords of every
// supported language are matched at once. This is data, not copy.
//
// Order matters: the first entry whose keywords occur in the name or title
// wins. `icon` is the name written to rackbook.yml (see iconChoices in
// src/lib/icons.ts). `en` holds regular-expression sources (lower case,
// matched against the lower-cased name and title); the Chinese lists hold
// plain words matched as substrings.

export type IconKeywords = {
  icon: string
  en: string[]
  zhCN: string[]
  zhTW: string[]
}

export const ICON_KEYWORDS: IconKeywords[] = [
  { icon: 'list-todo', en: ['todo'], zhCN: ['待办', '任务', '事项'], zhTW: ['待辦', '任務', '事項'] },
  { icon: 'list-checks', en: ['\\b(rules?|specs?)\\b'], zhCN: ['规范', '规则'], zhTW: ['規範', '規則'] },
  { icon: 'hash', en: ['\\bports?\\b'], zhCN: ['端口'], zhTW: ['端口', '連接埠', '通訊埠', '埠口'] },
  { icon: 'waypoints', en: ['range', 'cidr', 'subnet'], zhCN: ['网段', '地址池', '地址段'], zhTW: ['網段', '位址池', '位址段', '位址範圍'] },
  { icon: 'map-pin', en: ['site', 'location', 'room'], zhCN: ['站点', '机房', '位置', '地点'], zhTW: ['站點', '機房', '位置', '地點'] },
  { icon: 'plug', en: ['\\b(services?|apps?)\\b'], zhCN: ['服务', '应用'], zhTW: ['服務', '應用', '應用程式'] },
  { icon: 'network', en: ['address', 'addr', '\\bip'], zhCN: ['地址'], zhTW: ['位址', '地址'] },
  { icon: 'globe', en: ['domain', 'dns'], zhCN: ['域名'], zhTW: ['網域', '域名'] },
  {
    icon: 'server',
    en: ['device', 'host', 'server', 'machine', 'node'],
    zhCN: ['设备', '主机', '服务器', '机器', '节点'],
    zhTW: ['設備', '裝置', '主機', '伺服器', '機器', '節點'],
  },
  { icon: 'boxes', en: ['\\b(vms?|docker|containers?)\\b'], zhCN: ['虚拟', '容器'], zhTW: ['虛擬', '容器'] },
  { icon: 'hard-drive', en: ['storage', 'disk', 'volume'], zhCN: ['存储', '磁盘'], zhTW: ['儲存', '磁碟', '硬碟'] },
  { icon: 'archive', en: ['backup'], zhCN: ['备份'], zhTW: ['備份'] },
  { icon: 'shield-check', en: ['cert'], zhCN: ['证书'], zhTW: ['憑證', '證書'] },
  {
    icon: 'key-round',
    en: ['\\b(secrets?|credentials?|keys?)\\b'],
    zhCN: ['密钥', '凭据'],
    zhTW: ['金鑰', '密鑰', '憑據'],
  },
  { icon: 'users', en: ['user', 'account', 'member'], zhCN: ['账号', '用户', '成员'], zhTW: ['帳號', '帳戶', '使用者', '用戶', '成員'] },
  { icon: 'contact', en: ['contact'], zhCN: ['联系'], zhTW: ['聯絡', '聯繫'] },
  { icon: 'cable', en: ['\\b(cables?|links?)\\b'], zhCN: ['线缆', '链路'], zhTW: ['線纜', '纜線', '鏈路', '連結'] },
]
