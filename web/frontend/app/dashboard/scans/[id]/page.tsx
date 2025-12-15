'use client'

import { useEffect, useState, useCallback, useMemo } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { api } from '@/lib/api'
import { ScanRun, SecurityFinding } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { formatDate, getSeverityColor } from '@/lib/utils'
import { ArrowLeft, Wifi, WifiOff } from 'lucide-react'
import Link from 'next/link'
import { useScanWebSocket } from '@/hooks/useWebSocket'

export default function ScanDetailsPage() {
  const params = useParams()
  const router = useRouter()
  const scanId = parseInt(params.id as string)

  const [loading, setLoading] = useState(true)
  const [scan, setScan] = useState<ScanRun | null>(null)
  const [findings, setFindings] = useState<SecurityFinding[]>([])
  const [error, setError] = useState<string | null>(null)

  // Determine if scan is running for WebSocket subscription
  const isRunning = scan?.status === 'running' || scan?.status === 'pending'
  const runningScanIds = useMemo(() => (isRunning ? [scanId] : []), [isRunning, scanId])

  // Handle WebSocket updates for this scan
  const handleScanUpdate = useCallback((updatedScanId: number, message: any) => {
    if (updatedScanId !== scanId) return

    if (message.type === 'scan_progress') {
      setScan(prev => prev ? {
        ...prev,
        progress_percent: message.data.progress_percent ?? prev.progress_percent,
        progress_message: message.data.progress_message ?? prev.progress_message,
        items_processed: message.data.items_processed ?? prev.items_processed,
        estimated_total: message.data.estimated_total ?? prev.estimated_total,
      } : null)
    } else if (message.type === 'scan_status') {
      setScan(prev => prev ? {
        ...prev,
        status: message.status,
        end_time: message.details?.end_time ?? prev.end_time,
      } : null)
    } else if (message.type === 'scan_completed' || message.type === 'scan_failed') {
      // Refetch to get full updated data including findings
      fetchData()
    }
  }, [scanId])

  // WebSocket connection for real-time updates
  const { isConnected: wsConnected } = useScanWebSocket(runningScanIds, handleScanUpdate)

  const fetchData = async () => {
    try {
      const [scanData, findingsData] = await Promise.all([
        api.getScanDetails(scanId),
        api.getScanSecurityFindings(scanId),
      ])
      setScan(scanData)
      setFindings(findingsData)
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load scan details')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (scanId) {
      fetchData()
    }
  }, [scanId])

  // Fallback polling when WebSocket is not connected and scan is running
  useEffect(() => {
    if (!isRunning || wsConnected) return

    const interval = setInterval(() => {
      fetchData()
    }, 3000) // Fallback: Refresh every 3 seconds when WS not connected

    return () => clearInterval(interval)
  }, [isRunning, wsConnected])

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center space-x-2">
          <Link href="/dashboard/scans" className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <h1 className="text-3xl font-bold">Scan Details</h1>
        </div>
        <p className="text-muted-foreground">Loading...</p>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="space-y-6">
        <div className="flex items-center space-x-2">
          <Link href="/dashboard/scans" className="text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-5 w-5" />
          </Link>
          <h1 className="text-3xl font-bold">Scan Details</h1>
        </div>
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-700">{error || 'Scan not found'}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-2">
        <Link href="/dashboard/scans" className="text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-3xl font-bold">
              {scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)} Scan
            </h1>
            {isRunning && (
              <span
                className={`flex items-center gap-1 text-xs px-2 py-1 rounded-full ${
                  wsConnected
                    ? 'bg-green-100 dark:bg-green-900 text-green-700 dark:text-green-300'
                    : 'bg-yellow-100 dark:bg-yellow-900 text-yellow-700 dark:text-yellow-300'
                }`}
                title={wsConnected ? 'Real-time updates active' : 'Polling for updates'}
              >
                {wsConnected ? <Wifi className="h-3 w-3" /> : <WifiOff className="h-3 w-3" />}
                {wsConnected ? 'Live' : 'Polling'}
              </span>
            )}
          </div>
          <p className="text-muted-foreground">{scan.domain_name}</p>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Status</CardTitle>
          </CardHeader>
          <CardContent>
            <Badge
              variant={
                scan.status === 'completed'
                  ? 'success'
                  : scan.status === 'failed' || scan.status === 'cancelled'
                  ? 'danger'
                  : scan.status === 'running' || scan.status === 'pending'
                  ? 'warning'
                  : 'secondary'
              }
            >
              {scan.status}
            </Badge>
            {/* Progress bar for running scans */}
            {(scan.status === 'running' || scan.status === 'pending') && (
              <div className="mt-3">
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-muted-foreground">
                    {scan.progress_message || 'Processing...'}
                  </span>
                  <span className="font-medium">{scan.progress_percent}%</span>
                </div>
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-primary transition-all duration-300"
                    style={{ width: `${scan.progress_percent}%` }}
                  />
                </div>
                {scan.items_processed > 0 && (
                  <div className="text-xs text-muted-foreground mt-1">
                    {scan.items_processed}{scan.estimated_total ? ` / ${scan.estimated_total}` : ''} items processed
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Items</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{scan.total_items}</div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Issues Found</CardTitle>
          </CardHeader>
          <CardContent>
            <div className={`text-2xl font-bold ${scan.issues_found > 0 ? 'text-orange-600' : ''}`}>
              {scan.issues_found}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Started</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-sm">{formatDate(scan.start_time)}</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Findings ({findings.length})</CardTitle>
        </CardHeader>
        <CardContent>
          {findings.length === 0 ? (
            <p className="text-muted-foreground">No findings for this scan</p>
          ) : (
            <div className="space-y-4">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  className="rounded-lg border p-4"
                >
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                          {finding.severity}
                        </span>
                        <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${finding.passed ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                          {finding.passed ? 'Passed' : 'Failed'}
                        </span>
                      </div>
                      <h3 className="font-medium">{finding.title}</h3>
                      <p className="text-sm text-muted-foreground">{finding.description}</p>
                    </div>
                  </div>

                  {finding.remediation && !finding.passed && (
                    <div className="mt-3 rounded-md bg-blue-50 p-3">
                      <p className="text-sm font-medium text-blue-800">Remediation</p>
                      <p className="mt-1 text-sm text-blue-700">{finding.remediation}</p>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
