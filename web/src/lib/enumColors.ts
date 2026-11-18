import { t } from '@/i18n/zh-CN'

/** Badge colours an enum value can have (stored by name in x-rackbook-enum-colors). */
export const ENUM_COLORS = ['gray', 'red', 'orange', 'yellow', 'green', 'blue', 'purple'] as const

export const enumColorClass: Record<string, string> = {
  gray: 'bg-muted text-muted-foreground',
  red: 'bg-red-500/15 text-red-700 dark:text-red-300',
  orange: 'bg-orange-500/15 text-orange-700 dark:text-orange-300',
  yellow: 'bg-yellow-500/20 text-yellow-800 dark:text-yellow-300',
  green: 'bg-green-500/15 text-green-700 dark:text-green-300',
  blue: 'bg-blue-500/15 text-blue-700 dark:text-blue-300',
  purple: 'bg-purple-500/15 text-purple-700 dark:text-purple-300',
}

export const enumColorLabel = (c: string) => t.types.dialog.colors[c] ?? c
