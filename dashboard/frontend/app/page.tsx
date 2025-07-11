'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { DashboardLayout } from '@/components/layout/dashboard-layout'
import { StatsCard } from '@/components/ui/stats-card'
import { RecentActivity } from '@/components/dashboard/recent-activity'
import { KeyDistribution } from '@/components/dashboard/key-distribution'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api-client'
import { Shield, Key, RotateCw, Activity } from 'lucide-react'

export default function DashboardPage() {
  const { user, isLoading: authLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/login')
    }
  }, [user, authLoading, router])

  const { data: analytics, isLoading } = useQuery({
    queryKey: ['analytics-overview'],
    queryFn: async () => {
      const response = await api.analytics.overview()
      return response.data
    },
    enabled: !!user,
  })

  if (authLoading || isLoading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
      </div>
    )
  }

  return (
    <DashboardLayout>
      <div className="space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground mt-2">
            Welcome back! Here's an overview of your API key storage.
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatsCard
            title="Total Keys"
            value={analytics?.total_keys || 0}
            icon={Key}
            description="Active API keys"
          />
          <StatsCard
            title="Services"
            value={analytics?.total_services || 0}
            icon={Shield}
            description="Connected services"
          />
          <StatsCard
            title="Accessed Today"
            value={analytics?.keys_accessed_today || 0}
            icon={Activity}
            description="Keys used today"
          />
          <StatsCard
            title="Due for Rotation"
            value={analytics?.upcoming_rotations || 0}
            icon={RotateCw}
            description="Keys needing rotation"
            variant="warning"
          />
        </div>

        {/* Charts and Activity */}
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-7">
          <div className="col-span-4">
            <KeyDistribution />
          </div>
          <div className="col-span-3">
            <RecentActivity activities={analytics?.recent_activity || []} />
          </div>
        </div>
      </div>
    </DashboardLayout>
  )
}