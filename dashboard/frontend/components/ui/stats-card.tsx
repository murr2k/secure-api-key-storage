import { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface StatsCardProps {
  title: string
  value: number | string
  icon: LucideIcon
  description?: string
  variant?: 'default' | 'warning' | 'danger' | 'success'
}

const variantStyles = {
  default: 'bg-card',
  warning: 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800',
  danger: 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800',
  success: 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800',
}

const iconStyles = {
  default: 'text-muted-foreground',
  warning: 'text-yellow-600 dark:text-yellow-400',
  danger: 'text-red-600 dark:text-red-400',
  success: 'text-green-600 dark:text-green-400',
}

export function StatsCard({ 
  title, 
  value, 
  icon: Icon, 
  description,
  variant = 'default' 
}: StatsCardProps) {
  return (
    <div className={cn(
      "rounded-lg border p-6 transition-colors",
      variantStyles[variant]
    )}>
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          <p className="text-2xl font-bold">{value}</p>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
        </div>
        <div className={cn(
          "rounded-full p-3",
          variant === 'default' ? 'bg-accent' : ''
        )}>
          <Icon className={cn("h-6 w-6", iconStyles[variant])} />
        </div>
      </div>
    </div>
  )
}