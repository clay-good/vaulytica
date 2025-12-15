'use client'

import { useEffect, useState } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { api } from '@/lib/api'
import { ScanRun, Domain, ScanComparisonResult } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { FormField, Select } from '@/components/ui/form-input'
import { useToast } from '@/components/ui/toast'
import { formatDate } from '@/lib/utils'
import {
  ArrowLeft,
  ArrowRight,
  ArrowUp,
  ArrowDown,
  CheckCircle,
  XCircle,
  Minus,
  GitCompare,
  Loader2,
  AlertTriangle,
} from 'lucide-react'

export default function ScanComparePage() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const { error: showError } = useToast()

  const [loading, setLoading] = useState(false)
  const [scans, setScans] = useState<ScanRun[]>([])
  const [domains, setDomains] = useState<Domain[]>([])
  const [comparison, setComparison] = useState<ScanComparisonResult | null>(null)
  const [loadingScans, setLoadingScans] = useState(true)

  // Selection state
  const [selectedDomain, setSelectedDomain] = useState<string>('')
  const [selectedScanType, setSelectedScanType] = useState<string>('')
  const [scanId1, setScanId1] = useState<number | null>(null)
  const [scanId2, setScanId2] = useState<number | null>(null)

  // Get initial values from URL params
  useEffect(() => {
    const id1 = searchParams.get('scan1')
    const id2 = searchParams.get('scan2')
    if (id1) setScanId1(Number(id1))
    if (id2) setScanId2(Number(id2))
  }, [searchParams])

  // Load domains and scans
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [domainsData, scansData] = await Promise.all([
          api.getDomains(),
          api.getRecentScans(undefined, undefined, 100),
        ])
        setDomains(domainsData)
        setScans(scansData)
      } catch (err: any) {
        showError('Failed to load data', err.response?.data?.detail || 'Please try again.')
      } finally {
        setLoadingScans(false)
      }
    }
    fetchData()
  }, [])

  // Filter scans by domain and type
  const filteredScans = scans.filter(scan => {
    if (selectedDomain && scan.domain_name !== selectedDomain) return false
    if (selectedScanType && scan.scan_type !== selectedScanType) return false
    return scan.status === 'completed'
  })

  // Get available scan types
  const scanTypes = Array.from(new Set(scans.map(s => s.scan_type)))

  // Load comparison when both scans are selected
  const handleCompare = async () => {
    if (!scanId1 || !scanId2) {
      showError('Select scans', 'Please select two scans to compare.')
      return
    }
    if (scanId1 === scanId2) {
      showError('Same scan', 'Please select two different scans to compare.')
      return
    }

    setLoading(true)
    try {
      const result = await api.compareScans(scanId1, scanId2)
      setComparison(result)
      // Update URL
      router.push(`/dashboard/scans/compare?scan1=${scanId1}&scan2=${scanId2}`)
    } catch (err: any) {
      showError('Comparison failed', err.response?.data?.detail || 'Please try again.')
      setComparison(null)
    } finally {
      setLoading(false)
    }
  }

  // Auto-compare if URL params are present
  useEffect(() => {
    if (scanId1 && scanId2 && !comparison && !loading) {
      handleCompare()
    }
  }, [scanId1, scanId2])

  const getScanLabel = (scan: ScanRun) => {
    return `#${scan.id} - ${scan.scan_type} - ${formatDate(scan.start_time)}`
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Link
              href="/dashboard/scans"
              className="text-muted-foreground hover:text-foreground"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>
            <h1 className="text-3xl font-bold">Compare Scans</h1>
          </div>
          <p className="text-muted-foreground">
            Compare findings between two scan runs to track changes over time
          </p>
        </div>
      </div>

      {/* Scan Selection */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <GitCompare className="h-5 w-5" />
            Select Scans to Compare
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loadingScans ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <>
              {/* Filters */}
              <div className="grid gap-4 md:grid-cols-2 mb-6">
                <FormField label="Filter by Domain">
                  <Select
                    value={selectedDomain}
                    onChange={(e) => {
                      setSelectedDomain(e.target.value)
                      setScanId1(null)
                      setScanId2(null)
                      setComparison(null)
                    }}
                  >
                    <option value="">All Domains</option>
                    {domains.map((domain) => (
                      <option key={domain.id} value={domain.name}>
                        {domain.display_name || domain.name}
                      </option>
                    ))}
                  </Select>
                </FormField>
                <FormField label="Filter by Scan Type">
                  <Select
                    value={selectedScanType}
                    onChange={(e) => {
                      setSelectedScanType(e.target.value)
                      setScanId1(null)
                      setScanId2(null)
                      setComparison(null)
                    }}
                  >
                    <option value="">All Types</option>
                    {scanTypes.map((type) => (
                      <option key={type} value={type}>
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </option>
                    ))}
                  </Select>
                </FormField>
              </div>

              {/* Scan Selection */}
              <div className="grid gap-4 md:grid-cols-2 mb-4">
                <FormField label="Older Scan (Baseline)" required>
                  <Select
                    value={scanId1 || ''}
                    onChange={(e) => {
                      setScanId1(Number(e.target.value) || null)
                      setComparison(null)
                    }}
                  >
                    <option value="">Select scan...</option>
                    {filteredScans.map((scan) => (
                      <option key={scan.id} value={scan.id} disabled={scan.id === scanId2}>
                        {getScanLabel(scan)}
                      </option>
                    ))}
                  </Select>
                </FormField>
                <FormField label="Newer Scan (Current)" required>
                  <Select
                    value={scanId2 || ''}
                    onChange={(e) => {
                      setScanId2(Number(e.target.value) || null)
                      setComparison(null)
                    }}
                  >
                    <option value="">Select scan...</option>
                    {filteredScans.map((scan) => (
                      <option key={scan.id} value={scan.id} disabled={scan.id === scanId1}>
                        {getScanLabel(scan)}
                      </option>
                    ))}
                  </Select>
                </FormField>
              </div>

              <button
                onClick={handleCompare}
                disabled={!scanId1 || !scanId2 || loading}
                className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <GitCompare className="h-4 w-4" />
                )}
                Compare Scans
              </button>
            </>
          )}
        </CardContent>
      </Card>

      {/* Comparison Results */}
      {comparison && (
        <>
          {/* Summary Cards */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">New Issues</p>
                    <p className="text-3xl font-bold text-red-600">
                      {comparison.summary.new_issues_count}
                    </p>
                  </div>
                  <div className="p-3 bg-red-100 rounded-full">
                    <ArrowUp className="h-6 w-6 text-red-600" />
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Resolved Issues</p>
                    <p className="text-3xl font-bold text-green-600">
                      {comparison.summary.resolved_issues_count}
                    </p>
                  </div>
                  <div className="p-3 bg-green-100 rounded-full">
                    <CheckCircle className="h-6 w-6 text-green-600" />
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Unchanged</p>
                    <p className="text-3xl font-bold text-gray-600">
                      {comparison.unchanged_count}
                    </p>
                  </div>
                  <div className="p-3 bg-gray-100 rounded-full">
                    <Minus className="h-6 w-6 text-gray-600" />
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">Change</p>
                    <p className={`text-3xl font-bold ${
                      comparison.summary.change_percentage > 0 ? 'text-red-600' :
                      comparison.summary.change_percentage < 0 ? 'text-green-600' : 'text-gray-600'
                    }`}>
                      {comparison.summary.change_percentage > 0 ? '+' : ''}
                      {comparison.summary.change_percentage}%
                    </p>
                  </div>
                  <div className={`p-3 rounded-full ${
                    comparison.summary.change_percentage > 0 ? 'bg-red-100' :
                    comparison.summary.change_percentage < 0 ? 'bg-green-100' : 'bg-gray-100'
                  }`}>
                    {comparison.summary.change_percentage > 0 ? (
                      <ArrowUp className="h-6 w-6 text-red-600" />
                    ) : comparison.summary.change_percentage < 0 ? (
                      <ArrowDown className="h-6 w-6 text-green-600" />
                    ) : (
                      <Minus className="h-6 w-6 text-gray-600" />
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Scan Details */}
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Baseline Scan</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Scan ID:</span>
                    <span>#{comparison.old_scan.id}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Type:</span>
                    <Badge variant="secondary">{comparison.scan_type}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Date:</span>
                    <span>{comparison.old_scan.start_time ? formatDate(comparison.old_scan.start_time) : 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Issues Found:</span>
                    <span className="font-medium">{comparison.old_scan.issues_found ?? 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Current Scan</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Scan ID:</span>
                    <span>#{comparison.new_scan.id}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Type:</span>
                    <Badge variant="secondary">{comparison.scan_type}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Date:</span>
                    <span>{comparison.new_scan.start_time ? formatDate(comparison.new_scan.start_time) : 'N/A'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Issues Found:</span>
                    <span className="font-medium">{comparison.new_scan.issues_found ?? 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* New Issues */}
          {comparison.new_issues.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-red-600">
                  <XCircle className="h-5 w-5" />
                  New Issues ({comparison.new_issues.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {comparison.new_issues.map((issue, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-red-50 rounded-lg border border-red-100"
                    >
                      <div>
                        {comparison.scan_type === 'posture' && (
                          <>
                            <p className="font-medium">{issue.title}</p>
                            <p className="text-sm text-muted-foreground">
                              {issue.check_id} - {issue.category}
                            </p>
                          </>
                        )}
                        {comparison.scan_type === 'files' && (
                          <>
                            <p className="font-medium">{issue.file_name}</p>
                            <p className="text-sm text-muted-foreground">
                              Risk Score: {issue.risk_score}
                              {issue.is_public && ' | Public'}
                              {issue.is_shared_externally && ' | Shared Externally'}
                            </p>
                          </>
                        )}
                        {comparison.scan_type === 'users' && (
                          <>
                            <p className="font-medium">{issue.email}</p>
                            <p className="text-sm text-muted-foreground">
                              {issue.display_name}
                              {issue.is_inactive && ' | Inactive'}
                              {!issue.two_factor_enabled && ' | No 2FA'}
                            </p>
                          </>
                        )}
                        {comparison.scan_type === 'oauth' && (
                          <>
                            <p className="font-medium">{issue.display_text || issue.client_id}</p>
                            <p className="text-sm text-muted-foreground">
                              Risk Score: {issue.risk_score} | {issue.scopes_count} scopes
                            </p>
                          </>
                        )}
                      </div>
                      {issue.severity && (
                        <Badge variant={
                          issue.severity === 'critical' ? 'danger' :
                          issue.severity === 'high' ? 'warning' : 'secondary'
                        }>
                          {issue.severity}
                        </Badge>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Resolved Issues */}
          {comparison.resolved_issues.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-green-600">
                  <CheckCircle className="h-5 w-5" />
                  Resolved Issues ({comparison.resolved_issues.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {comparison.resolved_issues.map((issue, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-green-50 rounded-lg border border-green-100"
                    >
                      <div>
                        {comparison.scan_type === 'posture' && (
                          <>
                            <p className="font-medium">{issue.title}</p>
                            <p className="text-sm text-muted-foreground">
                              {issue.check_id} - {issue.category}
                            </p>
                          </>
                        )}
                        {comparison.scan_type === 'files' && (
                          <>
                            <p className="font-medium">{issue.file_name}</p>
                            <p className="text-sm text-muted-foreground">
                              Previous Risk Score: {issue.old_risk_score}
                            </p>
                          </>
                        )}
                        {comparison.scan_type === 'users' && (
                          <>
                            <p className="font-medium">{issue.email}</p>
                            <p className="text-sm text-muted-foreground">{issue.display_name}</p>
                          </>
                        )}
                        {comparison.scan_type === 'oauth' && (
                          <>
                            <p className="font-medium">{issue.display_text || issue.client_id}</p>
                            <p className="text-sm text-muted-foreground">
                              Previous Risk Score: {issue.old_risk_score}
                            </p>
                          </>
                        )}
                      </div>
                      <Badge variant="success">Resolved</Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* No Changes */}
          {comparison.new_issues.length === 0 && comparison.resolved_issues.length === 0 && (
            <Card>
              <CardContent className="py-8 text-center">
                <CheckCircle className="h-12 w-12 text-green-600 mx-auto mb-4" />
                <p className="text-lg font-medium">No significant changes detected</p>
                <p className="text-sm text-muted-foreground">
                  The findings between these two scans are identical.
                </p>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
  )
}
