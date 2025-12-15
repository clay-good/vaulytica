'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { DashboardOverview } from '@/lib/types'
import { StatsCards } from '@/components/dashboard/stats-cards'
import { SecurityScore } from '@/components/dashboard/security-score'
import { FindingsChart } from '@/components/dashboard/findings-chart'
import { RecentScans } from '@/components/dashboard/recent-scans'
import { exportToPDF, formatPrintDate } from '@/lib/pdf-export'
import { Download } from 'lucide-react'

export default function DashboardPage() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<DashboardOverview | null>(null)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const overview = await api.getDashboardOverview()
        setData(overview)
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to load dashboard data')
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [])

  if (loading) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Security Dashboard</h1>
          <p className="text-muted-foreground">Loading...</p>
        </div>
        <StatsCards data={null} />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Security Dashboard</h1>
          <p className="text-red-600">{error}</p>
        </div>
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-700">
            Unable to load dashboard data. Please ensure the backend is running and try again.
          </p>
        </div>
      </div>
    )
  }

  const handleExportPDF = () => {
    exportToPDF({
      title: 'Vaulytica Security Dashboard Report',
      orientation: 'landscape',
      paperSize: 'a4'
    })
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold">Security Dashboard</h1>
          <p className="text-muted-foreground text-sm sm:text-base">
            Overview of your Google Workspace security posture
          </p>
        </div>
        <button
          onClick={handleExportPDF}
          className="flex items-center justify-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 print:hidden w-full sm:w-auto"
        >
          <Download className="h-4 w-4" />
          Export PDF
        </button>
      </div>

      {/* Print header - only shows when printing */}
      <div className="hidden print:block pdf-header">
        <h1 className="text-2xl font-bold">Vaulytica Security Dashboard Report</h1>
        <p className="text-sm text-gray-600">Generated: {formatPrintDate()}</p>
      </div>

      <StatsCards data={data} />

      <div className="grid gap-4 sm:gap-6 grid-cols-1 md:grid-cols-2">
        <SecurityScore score={data?.security_score || 0} />
        <FindingsChart data={data?.findings_by_severity || {}} />
      </div>

      <RecentScans scans={data?.recent_scans || []} />
    </div>
  )
}
