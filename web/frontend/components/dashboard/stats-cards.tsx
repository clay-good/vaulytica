'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { DashboardOverview } from '@/lib/types'
import { formatNumber } from '@/lib/utils'
import { Scan, AlertTriangle, FileWarning, Users, Key } from 'lucide-react'

interface StatsCardsProps {
  data: DashboardOverview | null
}

export function StatsCards({ data }: StatsCardsProps) {
  if (!data) {
    return (
      <div className="grid gap-3 sm:gap-4 grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5">
        {[...Array(5)].map((_, i) => (
          <Card key={i}>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 p-3 sm:p-6 sm:pb-2">
              <CardTitle className="text-xs sm:text-sm font-medium">Loading...</CardTitle>
            </CardHeader>
            <CardContent className="p-3 pt-0 sm:p-6 sm:pt-0">
              <div className="text-xl sm:text-2xl font-bold">-</div>
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  const stats = [
    {
      title: 'Total Scans',
      value: formatNumber(data.scan_stats.total_scans),
      description: `${data.scan_stats.success_rate.toFixed(1)}% success rate`,
      icon: Scan,
    },
    {
      title: 'Critical Findings',
      value: formatNumber(data.critical_findings),
      description: 'Require immediate attention',
      icon: AlertTriangle,
      className: data.critical_findings > 0 ? 'text-red-600' : '',
    },
    {
      title: 'High-Risk Files',
      value: formatNumber(data.high_risk_files),
      description: 'Files with sharing issues',
      icon: FileWarning,
      className: data.high_risk_files > 0 ? 'text-orange-600' : '',
    },
    {
      title: 'Inactive Users',
      value: formatNumber(data.inactive_users),
      description: 'Dormant accounts',
      icon: Users,
      className: data.inactive_users > 0 ? 'text-yellow-600' : '',
    },
    {
      title: 'Risky OAuth Apps',
      value: formatNumber(data.risky_oauth_apps),
      description: 'Third-party apps with risks',
      icon: Key,
      className: data.risky_oauth_apps > 0 ? 'text-orange-600' : '',
    },
  ]

  return (
    <div className="grid gap-3 sm:gap-4 grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5">
      {stats.map((stat) => (
        <Card key={stat.title}>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 p-3 sm:p-6 sm:pb-2">
            <CardTitle className="text-xs sm:text-sm font-medium truncate mr-2">{stat.title}</CardTitle>
            <stat.icon className="h-4 w-4 text-muted-foreground flex-shrink-0" />
          </CardHeader>
          <CardContent className="p-3 pt-0 sm:p-6 sm:pt-0">
            <div className={`text-xl sm:text-2xl font-bold ${stat.className || ''}`}>
              {stat.value}
            </div>
            <p className="text-xs text-muted-foreground line-clamp-1">{stat.description}</p>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
