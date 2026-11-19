import { PlugZap } from 'lucide-react'
import { GrantsList } from '@/components/GrantsList'
import { PageHeader } from '@/components/common'
import { t } from '@/i18n/zh-CN'

export default function AdminGrants() {
  return (
    <div>
      <PageHeader icon={<PlugZap />} title={t.oauth.grants.adminTitle} description={t.oauth.grants.adminDescription} />
      <GrantsList scope="admin" />
    </div>
  )
}
