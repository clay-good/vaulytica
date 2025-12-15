'use client'

import { useState, useEffect, useCallback } from 'react'
import api from '@/lib/api'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { FormField, Select } from '@/components/ui/form-input'
import { useToast } from '@/components/ui/toast'
import { usePermissions } from '@/contexts/PermissionsContext'
import type {
  Domain,
  ScanRun,
  FindingType,
  DeltaComparisonResult,
  FindingsTrendResult,
  DeduplicationResult,
} from '@/lib/types'

type TabType = 'compare' | 'trend' | 'dedup'

export default function DeltaTrackingPage() {
  const { toast } = useToast()
  const { permissions } = usePermissions()

  // State
  const [activeTab, setActiveTab] = useState<TabType>('compare')
  const [domains, setDomains] = useState<Domain[]>([])
  const [scans, setScans] = useState<ScanRun[]>([])
  const [selectedDomain, setSelectedDomain] = useState<string>('')
  const [findingType, setFindingType] = useState<FindingType>('security')
  const [scan1, setScan1] = useState<string>('')
  const [scan2, setScan2] = useState<string>('')

  // Results
  const [comparison, setComparison] = useState<DeltaComparisonResult | null>(null)
  const [trend, setTrend] = useState<FindingsTrendResult | null>(null)
  const [dedup, setDedup] = useState<DeduplicationResult | null>(null)

  // Loading states
  const [loadingDomains, setLoadingDomains] = useState(true)
  const [loadingScans, setLoadingScans] = useState(false)
  const [loadingResults, setLoadingResults] = useState(false)

  // Fetch domains on mount
  useEffect(() => {
    const fetchDomains = async () => {
      try {
        const data = await api.getDomains()
        setDomains(data)
        if (data.length > 0 && !selectedDomain) {
          setSelectedDomain(data[0].name)
        }
      } catch {
        toast.error('Failed to load domains')
      } finally {
        setLoadingDomains(false)
      }
    }
    fetchDomains()
  }, [])

  // Fetch scans when domain changes
  useEffect(() => {
    if (!selectedDomain) return

    const fetchScans = async () => {
      setLoadingScans(true)
      try {
        // Map finding type to scan type
        const scanTypeMap: Record<FindingType, string> = {
          security: 'posture',
          file: 'files',
          user: 'users',
          oauth: 'oauth',
        }
        const scanType = scanTypeMap[findingType]
        const data = await api.getRecentScans(selectedDomain, scanType, 20)
        const completedScans = data.filter((s) => s.status === 'completed')
        setScans(completedScans)

        // Reset scan selection
        setScan1('')
        setScan2('')
        setComparison(null)
      } catch {
        toast.error('Failed to load scans')
      } finally {
        setLoadingScans(false)
      }
    }
    fetchScans()
  }, [selectedDomain, findingType])

  // Compare scans
  const handleCompare = useCallback(async () => {
    if (!scan1 || !scan2) {
      toast.error('Please select two scans to compare')
      return
    }

    setLoadingResults(true)
    try {
      const result = await api.compareScansDelta(
        parseInt(scan1),
        parseInt(scan2),
        findingType
      )
      setComparison(result)
    } catch {
      toast.error('Failed to compare scans')
    } finally {
      setLoadingResults(false)
    }
  }, [scan1, scan2, findingType])

  // Get trend data
  const handleGetTrend = useCallback(async () => {
    if (!selectedDomain) {
      toast.error('Please select a domain')
      return
    }

    setLoadingResults(true)
    try {
      const result = await api.getFindingsTrend(selectedDomain, findingType, 10)
      setTrend(result)
    } catch {
      toast.error('Failed to load trend data')
    } finally {
      setLoadingResults(false)
    }
  }, [selectedDomain, findingType])

  // Analyze deduplication
  const handleDedup = useCallback(async () => {
    if (!scan1) {
      toast.error('Please select a scan to analyze')
      return
    }

    setLoadingResults(true)
    try {
      const result = await api.analyzeScanDeduplication(parseInt(scan1), findingType)
      setDedup(result)
    } catch {
      toast.error('Failed to analyze scan')
    } finally {
      setLoadingResults(false)
    }
  }, [scan1, findingType])

  const findingTypeOptions = [
    { value: 'security', label: 'Security Findings' },
    { value: 'file', label: 'File Findings' },
    { value: 'user', label: 'User Findings' },
    { value: 'oauth', label: 'OAuth Findings' },
  ]

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Delta Tracking
          </h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Track changes between scans and identify recurring findings
          </p>
        </div>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <FormField label="Domain">
            <Select
              value={selectedDomain}
              onChange={(e) => setSelectedDomain(e.target.value)}
              disabled={loadingDomains}
            >
              <option value="">Select domain</option>
              {domains.map((d) => (
                <option key={d.id} value={d.name}>
                  {d.display_name || d.name}
                </option>
              ))}
            </Select>
          </FormField>

          <FormField label="Finding Type">
            <Select
              value={findingType}
              onChange={(e) => setFindingType(e.target.value as FindingType)}
            >
              {findingTypeOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </Select>
          </FormField>
        </div>
      </Card>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          {(['compare', 'trend', 'dedup'] as TabType[]).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`
                whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm
                ${
                  activeTab === tab
                    ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400'
                }
              `}
            >
              {tab === 'compare' && 'Compare Scans'}
              {tab === 'trend' && 'Trend Analysis'}
              {tab === 'dedup' && 'Deduplication'}
            </button>
          ))}
        </nav>
      </div>

      {/* Compare Tab */}
      {activeTab === 'compare' && (
        <div className="space-y-4">
          <Card className="p-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
              <FormField label="Older Scan">
                <Select
                  value={scan1}
                  onChange={(e) => setScan1(e.target.value)}
                  disabled={loadingScans || scans.length === 0}
                >
                  <option value="">Select scan</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id.toString()}>
                      #{s.id} - {formatDate(s.start_time)} ({s.issues_found} issues)
                    </option>
                  ))}
                </Select>
              </FormField>

              <FormField label="Newer Scan">
                <Select
                  value={scan2}
                  onChange={(e) => setScan2(e.target.value)}
                  disabled={loadingScans || scans.length === 0}
                >
                  <option value="">Select scan</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id.toString()}>
                      #{s.id} - {formatDate(s.start_time)} ({s.issues_found} issues)
                    </option>
                  ))}
                </Select>
              </FormField>

              <button
                onClick={handleCompare}
                disabled={loadingResults || !scan1 || !scan2}
                className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loadingResults ? 'Comparing...' : 'Compare'}
              </button>
            </div>
          </Card>

          {comparison && (
            <div className="space-y-4">
              {/* Summary Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card className="p-4 bg-green-50 dark:bg-green-900/20">
                  <p className="text-sm text-green-600 dark:text-green-400">New</p>
                  <p className="text-2xl font-bold text-green-700 dark:text-green-300">
                    {comparison.summary.new_count}
                  </p>
                </Card>
                <Card className="p-4 bg-blue-50 dark:bg-blue-900/20">
                  <p className="text-sm text-blue-600 dark:text-blue-400">Resolved</p>
                  <p className="text-2xl font-bold text-blue-700 dark:text-blue-300">
                    {comparison.summary.resolved_count}
                  </p>
                </Card>
                <Card className="p-4 bg-yellow-50 dark:bg-yellow-900/20">
                  <p className="text-sm text-yellow-600 dark:text-yellow-400">Changed</p>
                  <p className="text-2xl font-bold text-yellow-700 dark:text-yellow-300">
                    {comparison.summary.changed_count}
                  </p>
                </Card>
                <Card className="p-4 bg-gray-50 dark:bg-gray-800">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Unchanged</p>
                  <p className="text-2xl font-bold text-gray-700 dark:text-gray-300">
                    {comparison.summary.unchanged_count}
                  </p>
                </Card>
              </div>

              {/* New Findings */}
              {comparison.new.length > 0 && (
                <Card className="p-4">
                  <h3 className="text-lg font-semibold mb-3 text-green-700 dark:text-green-400">
                    New Findings ({comparison.new.length})
                  </h3>
                  <div className="space-y-2">
                    {comparison.new.slice(0, 10).map((f) => (
                      <div
                        key={f.fingerprint}
                        className="p-3 bg-green-50 dark:bg-green-900/20 rounded-lg"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-gray-900 dark:text-white">
                            {f.summary.title || f.summary.file_name || f.summary.email || f.summary.display_text || `ID: ${f.id}`}
                          </span>
                          {f.summary.severity && (
                            <Badge variant={f.summary.severity === 'critical' || f.summary.severity === 'high' ? 'danger' : 'warning'}>
                              {f.summary.severity}
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                          Fingerprint: {f.fingerprint.substring(0, 16)}...
                        </p>
                      </div>
                    ))}
                    {comparison.new.length > 10 && (
                      <p className="text-sm text-gray-500">
                        And {comparison.new.length - 10} more...
                      </p>
                    )}
                  </div>
                </Card>
              )}

              {/* Resolved Findings */}
              {comparison.resolved.length > 0 && (
                <Card className="p-4">
                  <h3 className="text-lg font-semibold mb-3 text-blue-700 dark:text-blue-400">
                    Resolved Findings ({comparison.resolved.length})
                  </h3>
                  <div className="space-y-2">
                    {comparison.resolved.slice(0, 10).map((f) => (
                      <div
                        key={f.fingerprint}
                        className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-gray-900 dark:text-white">
                            {f.summary.title || f.summary.file_name || f.summary.email || f.summary.display_text || `ID: ${f.id}`}
                          </span>
                          {f.summary.severity && (
                            <Badge variant="success">{f.summary.severity}</Badge>
                          )}
                        </div>
                      </div>
                    ))}
                    {comparison.resolved.length > 10 && (
                      <p className="text-sm text-gray-500">
                        And {comparison.resolved.length - 10} more...
                      </p>
                    )}
                  </div>
                </Card>
              )}

              {/* Changed Findings */}
              {comparison.changed.length > 0 && (
                <Card className="p-4">
                  <h3 className="text-lg font-semibold mb-3 text-yellow-700 dark:text-yellow-400">
                    Changed Findings ({comparison.changed.length})
                  </h3>
                  <div className="space-y-2">
                    {comparison.changed.slice(0, 10).map((f) => (
                      <div
                        key={f.fingerprint}
                        className="p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg"
                      >
                        <div className="font-medium text-gray-900 dark:text-white">
                          {f.current_summary.title || f.current_summary.file_name || f.current_summary.email || f.current_summary.display_text || `ID: ${f.current_id}`}
                        </div>
                        <div className="mt-2 space-y-1">
                          {f.changes.map((change, idx) => (
                            <div key={idx} className="text-sm">
                              <span className="text-gray-600 dark:text-gray-400">
                                {change.field}:
                              </span>{' '}
                              <span className="text-red-600 dark:text-red-400 line-through">
                                {String(change.old_value)}
                              </span>{' '}
                              <span className="text-green-600 dark:text-green-400">
                                {String(change.new_value)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Card>
              )}
            </div>
          )}
        </div>
      )}

      {/* Trend Tab */}
      {activeTab === 'trend' && (
        <div className="space-y-4">
          <Card className="p-4">
            <div className="flex items-end gap-4">
              <button
                onClick={handleGetTrend}
                disabled={loadingResults || !selectedDomain}
                className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loadingResults ? 'Loading...' : 'Load Trend Data'}
              </button>
            </div>
          </Card>

          {trend && (
            <Card className="p-4">
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                Findings Trend - {trend.domain_name}
              </h3>

              <div className="overflow-x-auto">
                <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                  <thead>
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Scan
                      </th>
                      <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Date
                      </th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Total
                      </th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        New
                      </th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Resolved
                      </th>
                      <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">
                        Net Change
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                    {trend.data_points.map((point, idx) => (
                      <tr key={point.scan_id}>
                        <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">
                          #{point.scan_id}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                          {formatDate(point.scan_time)}
                        </td>
                        <td className="px-4 py-3 text-sm text-right font-medium text-gray-900 dark:text-white">
                          {point.total_findings}
                        </td>
                        <td className="px-4 py-3 text-sm text-right">
                          {point.new !== null ? (
                            <span className="text-green-600 dark:text-green-400">
                              +{point.new}
                            </span>
                          ) : (
                            <span className="text-gray-400">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm text-right">
                          {point.resolved !== null ? (
                            <span className="text-blue-600 dark:text-blue-400">
                              -{point.resolved}
                            </span>
                          ) : (
                            <span className="text-gray-400">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm text-right">
                          {point.net_change !== null ? (
                            <span
                              className={
                                point.net_change > 0
                                  ? 'text-red-600 dark:text-red-400'
                                  : point.net_change < 0
                                  ? 'text-green-600 dark:text-green-400'
                                  : 'text-gray-500'
                              }
                            >
                              {point.net_change > 0 ? '+' : ''}
                              {point.net_change}
                            </span>
                          ) : (
                            <span className="text-gray-400">-</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </div>
      )}

      {/* Deduplication Tab */}
      {activeTab === 'dedup' && (
        <div className="space-y-4">
          <Card className="p-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
              <FormField label="Select Scan to Analyze">
                <Select
                  value={scan1}
                  onChange={(e) => setScan1(e.target.value)}
                  disabled={loadingScans || scans.length === 0}
                >
                  <option value="">Select scan</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id.toString()}>
                      #{s.id} - {formatDate(s.start_time)} ({s.issues_found} issues)
                    </option>
                  ))}
                </Select>
              </FormField>

              <button
                onClick={handleDedup}
                disabled={loadingResults || !scan1}
                className="bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loadingResults ? 'Analyzing...' : 'Analyze'}
              </button>
            </div>
          </Card>

          {dedup && (
            <Card className="p-4">
              <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                Deduplication Analysis - Scan #{dedup.scan_id}
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total Findings</p>
                  <p className="text-3xl font-bold text-gray-900 dark:text-white">
                    {dedup.total}
                  </p>
                </div>

                <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                  <p className="text-sm text-green-600 dark:text-green-400">New Findings</p>
                  <p className="text-3xl font-bold text-green-700 dark:text-green-300">
                    {dedup.new}
                  </p>
                  <p className="text-xs text-green-600 dark:text-green-400 mt-1">
                    {dedup.total > 0
                      ? `${((dedup.new / dedup.total) * 100).toFixed(1)}%`
                      : '0%'}
                  </p>
                </div>

                <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                  <p className="text-sm text-yellow-600 dark:text-yellow-400">
                    Recurring Findings
                  </p>
                  <p className="text-3xl font-bold text-yellow-700 dark:text-yellow-300">
                    {dedup.recurring}
                  </p>
                  <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-1">
                    {dedup.total > 0
                      ? `${((dedup.recurring / dedup.total) * 100).toFixed(1)}%`
                      : '0%'}
                  </p>
                </div>
              </div>

              {dedup.previous_scan_id && (
                <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
                  Compared against previous scan #{dedup.previous_scan_id}
                </p>
              )}

              {!dedup.previous_scan_id && (
                <p className="mt-4 text-sm text-gray-500 dark:text-gray-400">
                  This is the first scan - all findings are new
                </p>
              )}
            </Card>
          )}
        </div>
      )}
    </div>
  )
}
