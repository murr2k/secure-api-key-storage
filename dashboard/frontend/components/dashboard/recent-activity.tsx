import { formatDate } from '@/lib/utils'
import { Activity, Key, RotateCw, Trash2, Edit, Eye } from 'lucide-react'

interface ActivityItem {
  id: string
  timestamp: string
  action: string
  key_name?: string
  user: string
  details: any
}

interface RecentActivityProps {
  activities: ActivityItem[]
}

const actionIcons: Record<string, any> = {
  key_created: Key,
  key_accessed: Eye,
  key_updated: Edit,
  key_deleted: Trash2,
  key_rotated: RotateCw,
}

const actionColors: Record<string, string> = {
  key_created: 'text-green-600 bg-green-100 dark:text-green-400 dark:bg-green-900/20',
  key_accessed: 'text-blue-600 bg-blue-100 dark:text-blue-400 dark:bg-blue-900/20',
  key_updated: 'text-yellow-600 bg-yellow-100 dark:text-yellow-400 dark:bg-yellow-900/20',
  key_deleted: 'text-red-600 bg-red-100 dark:text-red-400 dark:bg-red-900/20',
  key_rotated: 'text-purple-600 bg-purple-100 dark:text-purple-400 dark:bg-purple-900/20',
}

export function RecentActivity({ activities }: RecentActivityProps) {
  return (
    <div className="rounded-lg border bg-card p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Recent Activity</h3>
        <Activity className="h-5 w-5 text-muted-foreground" />
      </div>
      
      <div className="space-y-4">
        {activities.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            No recent activity
          </p>
        ) : (
          activities.map((activity) => {
            const Icon = actionIcons[activity.action] || Activity
            const colorClass = actionColors[activity.action] || 'text-gray-600 bg-gray-100'
            
            return (
              <div key={activity.id} className="flex items-start space-x-3">
                <div className={`rounded-full p-2 ${colorClass}`}>
                  <Icon className="h-4 w-4" />
                </div>
                <div className="flex-1 space-y-1">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium">
                      {activity.action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {formatDate(activity.timestamp)}
                    </p>
                  </div>
                  {activity.key_name && (
                    <p className="text-sm text-muted-foreground">
                      Key: <span className="font-mono">{activity.key_name}</span>
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground">
                    by {activity.user}
                  </p>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}