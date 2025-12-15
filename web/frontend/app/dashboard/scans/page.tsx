'use client'

import { useEffect, useState, useCallback, useMemo } from 'react'
import Link from 'next/link'
import { api } from '@/lib/api'
import { ScanRun, Domain } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ScansPageSkeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { FormField, Select } from '@/components/ui/form-input'
import { formatDate } from '@/lib/utils'
import { Play, X, Loader2, Plus, StopCircle, GitCompare, Wifi, WifiOff } from 'lucide-react'
import { usePermissions } from '@/contexts/PermissionsContext'
import { useScanWebSocket } from '@/hooks/useWebSocket'

export default function ScansPage() {
  const [loading, setLoading] = useState(true)
  const [scans, setScans] = useState<ScanRun[]>([])
  const [domains, setDomains] = useState<Domain[]>([])
  const [error, setError] = useState<string | null>(null)
  const [showRunDialog, setShowRunDialog] = useState(false)
  const [triggering, setTriggering] = useState(false)
  const [cancellingId, setCancellingId] = useState<number | null>(null)
  const { success, error: showError } = useToast()
  const { canEdit, permissions } = usePermissions()

  // Run scan form state
  const [selectedDomain, setSelectedDomain] = useState('')
  const [selectedScanType, setSelectedScanType] = useState('all')

  // Check if user can trigger scans on any domain
  const canTriggerScans = permissions?.is_superuser || (permissions?.editable_domains.length ?? 0) > 0

  // Filter domains to only show ones user can edit
  const editableDomains = domains.filter(d => canEdit(d.name))

  // Get IDs of running scans for WebSocket subscription
  const runningScanIds = useMemo(() =>
    scans.filter(s => s.status === 'running' || s.status === 'pending').map(s => s.id),
    [scans]
  )

  // Handle WebSocket updates for running scans
  const handleScanUpdate = useCallback((scanId: number, message: any) => {
    setScans(prevScans => prevScans.map(scan => {
      if (scan.id !== scanId) return scan

      if (message.type === 'scan_progress') {
        return {
          ...scan,
          progress_percent: message.data.progress_percent ?? scan.progress_percent,
          progress_message: message.data.progress_message ?? scan.progress_message,
          items_processed: message.data.items_processed ?? scan.items_processed,
          estimated_total: message.data.estimated_total ?? scan.estimated_total,
        }
      } else if (message.type === 'scan_status') {
        return {
          ...scan,
          status: message.status,
          end_time: message.details?.end_time ?? scan.end_time,
        }
      } else if (message.type === 'scan_completed' || message.type === 'scan_failed') {
        // Refetch to get full updated data
        fetchData()
        return scan
      }
      return scan
    }))
  }, [])

  // WebSocket connection for real-time updates
  const { isConnected: wsConnected } = useScanWebSocket(runningScanIds, handleScanUpdate)

  const fetchData = async () => {
    try {
      const [scansData, domainsData] = await Promise.all([
        api.getRecentScans(undefined, undefined, 50),
        api.getDomains(),
      ])
      setScans(scansData)
      setDomains(domainsData)
      if (domainsData.length > 0 && !selectedDomain) {
        setSelectedDomain(domainsData[0].name)
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load scans')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  // Fallback polling when WebSocket is not connected and there are running scans
  useEffect(() => {
    const hasRunningScans = scans.some(s => s.status === 'running' || s.status === 'pending')
    if (!hasRunningScans || wsConnected) return

    const interval = setInterval(() => {
      fetchData()
    }, 5000) // Fallback: Refresh every 5 seconds when WS not connected

    return () => clearInterval(interval)
  }, [scans, wsConnected])

  const handleTriggerScan = async () => {
    if (!selectedDomain) {
      showError('No domain selected', 'Please select a domain to scan.')
      return
    }

    setTriggering(true)
    try {
      const result = await api.triggerScan({
        domain_name: selectedDomain,
        scan_type: selectedScanType,
      })
      setShowRunDialog(false)
      success('Scan started', result.message)
      // Refresh the scans list
      await fetchData()
    } catch (err: any) {
      showError('Failed to start scan', err.response?.data?.detail || 'Please try again.')
    } finally {
      setTriggering(false)
    }
  }

  const handleCancelScan = async (scanId: number) => {
    if (!confirm('Are you sure you want to cancel this scan?')) return

    setCancellingId(scanId)
    try {
      const result = await api.cancelScan(scanId)
      success('Scan cancelled', result.message)
      await fetchData()
    } catch (err: any) {
      showError('Failed to cancel scan', err.response?.data?.detail || 'Please try again.')
    } finally {
      setCancellingId(null)
    }
  }

  if (loading) {
    return <ScansPageSkeleton />
  }

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold">Scans</h1>
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl sm:text-3xl font-bold">Scans</h1>
            {runningScanIds.length > 0 && (
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
          <p className="text-muted-foreground text-sm sm:text-base">
            View all security scan runs and their results
          </p>
        </div>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <Link
            href="/dashboard/scans/compare"
            className="flex items-center justify-center space-x-2 rounded-md border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-700"
          >
            <GitCompare className="h-4 w-4" />
            <span>Compare Scans</span>
          </Link>
          {canTriggerScans && (
            <button
              onClick={() => setShowRunDialog(true)}
              className="flex items-center justify-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
            >
              <Play className="h-4 w-4" />
              <span>Run Scan Now</span>
            </button>
          )}
        </div>
      </div>

      {/* Run Scan Dialog */}
      {showRunDialog && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Run Scan Now</CardTitle>
                <CardDescription>Start a new security scan immediately</CardDescription>
              </div>
              <button
                onClick={() => setShowRunDialog(false)}
                className="rounded-md p-1 hover:bg-gray-100"
              >
                <X className="h-5 w-5 text-muted-foreground" />
              </button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid gap-4 md:grid-cols-2">
              <FormField label="Domain" required>
                <Select
                  value={selectedDomain}
                  onChange={(e) => setSelectedDomain(e.target.value)}
                >
                  {editableDomains.length === 0 && (
                    <option value="">No domains available</option>
                  )}
                  {editableDomains.map((domain) => (
                    <option key={domain.id} value={domain.name}>
                      {domain.display_name || domain.name}
                    </option>
                  ))}
                </Select>
              </FormField>
              <FormField label="Scan Type">
                <Select
                  value={selectedScanType}
                  onChange={(e) => setSelectedScanType(e.target.value)}
                >
                  <option value="all">All Scans</option>
                  <option value="posture">Security Posture</option>
                  <option value="files">Files</option>
                  <option value="users">Users</option>
                  <option value="oauth">OAuth Apps</option>
                </Select>
              </FormField>
            </div>
            <div className="mt-4 flex space-x-2">
              <button
                onClick={handleTriggerScan}
                disabled={triggering || editableDomains.length === 0}
                className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {triggering && <Loader2 className="h-4 w-4 animate-spin" />}
                <span>{triggering ? 'Starting...' : 'Start Scan'}</span>
              </button>
              <button
                type="button"
                onClick={() => setShowRunDialog(false)}
                className="rounded-md border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
            {editableDomains.length === 0 && (
              <p className="mt-3 text-sm text-muted-foreground">
                No domains available. You need editor or admin role for at least one domain to run scans.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Scan History</CardTitle>
        </CardHeader>
        <CardContent>
          {scans.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-muted-foreground mb-4">
                {canTriggerScans
                  ? 'No scans found. Click "Run Scan Now" to start your first scan.'
                  : 'No scans found.'}
              </p>
              {canTriggerScans && (
                <button
                  onClick={() => setShowRunDialog(true)}
                  className="inline-flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                >
                  <Play className="h-4 w-4" />
                  <span>Run Scan Now</span>
                </button>
              )}
            </div>
          ) : (
            <>
              {/* Mobile card view */}
              <div className="space-y-3 md:hidden">
                {scans.map((scan) => (
                  <div key={scan.id} className="rounded-lg border border-gray-200 dark:border-gray-700 p-4 space-y-3">
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="font-medium">
                          {scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)} Scan
                        </p>
                        <p className="text-sm text-muted-foreground">{scan.domain_name}</p>
                      </div>
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
                    </div>

                    {(scan.status === 'running' || scan.status === 'pending') && (
                      <div>
                        <div className="flex items-center justify-between text-xs mb-1">
                          <span className="text-muted-foreground">
                            {scan.progress_message || 'Processing...'}
                          </span>
                          <span className="font-medium">{scan.progress_percent}%</span>
                        </div>
                        <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary transition-all duration-300"
                            style={{ width: `${scan.progress_percent}%` }}
                          />
                        </div>
                      </div>
                    )}

                    <div className="flex items-center justify-between text-sm">
                      <div className="flex gap-4">
                        <span><strong>{scan.total_items}</strong> items</span>
                        <span className={scan.issues_found > 0 ? 'text-orange-600 font-medium' : ''}>
                          <strong>{scan.issues_found}</strong> issues
                        </span>
                      </div>
                      <span className="text-muted-foreground text-xs">{formatDate(scan.start_time)}</span>
                    </div>

                    <div className="flex items-center gap-2 pt-2 border-t border-gray-200 dark:border-gray-700">
                      <Link
                        href={`/dashboard/scans/${scan.id}`}
                        className="text-sm text-primary hover:underline"
                      >
                        View Details
                      </Link>
                      {(scan.status === 'running' || scan.status === 'pending') && canEdit(scan.domain_name) && (
                        <button
                          onClick={() => handleCancelScan(scan.id)}
                          disabled={cancellingId === scan.id}
                          className="rounded p-1 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
                          title="Cancel scan"
                        >
                          {cancellingId === scan.id ? (
                            <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                          ) : (
                            <StopCircle className="h-4 w-4 text-red-600" />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Desktop table view */}
              <div className="hidden md:block overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b text-left">
                      <th className="pb-3 font-medium">Type</th>
                      <th className="pb-3 font-medium">Domain</th>
                      <th className="pb-3 font-medium">Status</th>
                      <th className="pb-3 font-medium">Progress</th>
                      <th className="pb-3 font-medium">Items</th>
                      <th className="pb-3 font-medium">Issues</th>
                      <th className="pb-3 font-medium">Started</th>
                      <th className="pb-3 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((scan) => (
                      <tr key={scan.id} className="border-b">
                        <td className="py-3">
                          {scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)}
                        </td>
                        <td className="py-3">{scan.domain_name}</td>
                        <td className="py-3">
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
                        </td>
                        <td className="py-3">
                          {(scan.status === 'running' || scan.status === 'pending') ? (
                            <div className="w-32">
                              <div className="flex items-center justify-between text-xs mb-1">
                                <span className="text-muted-foreground">
                                  {scan.progress_message || 'Processing...'}
                                </span>
                                <span className="font-medium">{scan.progress_percent}%</span>
                              </div>
                              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-primary transition-all duration-300"
                                  style={{ width: `${scan.progress_percent}%` }}
                                />
                              </div>
                              {scan.items_processed > 0 && (
                                <div className="text-xs text-muted-foreground mt-1">
                                  {scan.items_processed}{scan.estimated_total ? ` / ${scan.estimated_total}` : ''} items
                                </div>
                              )}
                            </div>
                          ) : (
                            <span className="text-muted-foreground">—</span>
                          )}
                        </td>
                        <td className="py-3">{scan.total_items}</td>
                        <td className="py-3">
                          <span className={scan.issues_found > 0 ? 'text-orange-600 font-medium' : ''}>
                            {scan.issues_found}
                          </span>
                        </td>
                        <td className="py-3 text-sm text-muted-foreground">
                          {formatDate(scan.start_time)}
                        </td>
                        <td className="py-3">
                          <div className="flex items-center space-x-2">
                            <Link
                              href={`/dashboard/scans/${scan.id}`}
                              className="text-sm text-primary hover:underline"
                            >
                              View
                            </Link>
                            {(scan.status === 'running' || scan.status === 'pending') && canEdit(scan.domain_name) && (
                              <button
                                onClick={() => handleCancelScan(scan.id)}
                                disabled={cancellingId === scan.id}
                                className="rounded p-1 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50"
                                title="Cancel scan"
                              >
                                {cancellingId === scan.id ? (
                                  <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                                ) : (
                                  <StopCircle className="h-4 w-4 text-red-600" />
                                )}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
