'use client'

import Link from 'next/link'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ScanRun } from '@/lib/types'
import { formatDate, getStatusColor } from '@/lib/utils'

interface RecentScansProps {
  scans: ScanRun[]
}

export function RecentScans({ scans }: RecentScansProps) {
  if (scans.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">No scans found</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between p-4 sm:p-6">
        <CardTitle className="text-base sm:text-lg">Recent Scans</CardTitle>
        <Link
          href="/dashboard/scans"
          className="text-sm text-primary hover:underline"
        >
          View all
        </Link>
      </CardHeader>
      <CardContent className="p-4 pt-0 sm:p-6 sm:pt-0">
        <div className="space-y-3 sm:space-y-4">
          {scans.map((scan) => (
            <div
              key={scan.id}
              className="flex flex-col sm:flex-row sm:items-center sm:justify-between rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-3 sm:p-4 gap-2 sm:gap-4"
            >
              <div className="space-y-1 min-w-0">
                <Link
                  href={`/dashboard/scans/${scan.id}`}
                  className="font-medium hover:underline text-sm sm:text-base"
                >
                  {scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)} Scan
                </Link>
                <p className="text-xs sm:text-sm text-muted-foreground truncate">
                  {scan.domain_name} - {formatDate(scan.start_time)}
                </p>
              </div>

              <div className="flex items-center justify-between sm:justify-end gap-3 sm:gap-4">
                <div className="text-left sm:text-right">
                  <p className="text-xs sm:text-sm font-medium">{scan.total_items} items</p>
                  <p className="text-xs text-muted-foreground">
                    {scan.issues_found} issues
                  </p>
                </div>

                <Badge
                  variant={
                    scan.status === 'completed'
                      ? 'success'
                      : scan.status === 'failed'
                      ? 'danger'
                      : 'secondary'
                  }
                >
                  {scan.status}
                </Badge>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
