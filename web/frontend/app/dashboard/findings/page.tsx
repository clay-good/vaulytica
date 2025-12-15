'use client'

import { useEffect, useState, useMemo } from 'react'
import { useSearchParams } from 'next/navigation'
import Link from 'next/link'
import { api } from '@/lib/api'
import { SecurityFinding, FileFinding, UserFinding, OAuthFinding } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { FindingsPageSkeleton, CardListSkeleton, TableSkeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { formatDate, getSeverityColor } from '@/lib/utils'
import { Download, Loader2, Search, Filter, ArrowUpDown, ChevronUp, ChevronDown, ChevronRight, FileText } from 'lucide-react'
import { exportToPDF, formatPrintDate } from '@/lib/pdf-export'

type FindingType = 'security' | 'files' | 'users' | 'oauth'
type SortDirection = 'asc' | 'desc'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

const SEVERITY_ORDER: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
}

export default function FindingsPage() {
  const searchParams = useSearchParams()
  const type = (searchParams.get('type') as FindingType) || 'security'
  const { success, error: showError } = useToast()

  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState<'csv' | 'json' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [securityFindings, setSecurityFindings] = useState<SecurityFinding[]>([])
  const [fileFindings, setFileFindings] = useState<FileFinding[]>([])
  const [userFindings, setUserFindings] = useState<UserFinding[]>([])
  const [oauthFindings, setOAuthFindings] = useState<OAuthFinding[]>([])

  // Filter and sort state
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')
  const [sortField, setSortField] = useState<string>('severity')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')

  const handleExportPDF = () => {
    const typeLabels: Record<FindingType, string> = {
      security: 'Security Posture',
      files: 'File Sharing',
      users: 'User',
      oauth: 'OAuth Application'
    }
    exportToPDF({
      title: `${typeLabels[type]} Findings Report - Vaulytica`,
      orientation: 'landscape',
      paperSize: 'a4'
    })
  }

  const handleExport = async (format: 'csv' | 'json') => {
    setExporting(format)
    const token = localStorage.getItem('access_token')
    const url = `${API_BASE_URL}/api/findings/export/${type}?format=${format}`

    try {
      const response = await fetch(url, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (!response.ok) {
        throw new Error('Export failed')
      }

      const blob = await response.blob()
      const downloadUrl = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = downloadUrl
      a.download = `${type}_findings.${format}`
      document.body.appendChild(a)
      a.click()
      a.remove()
      window.URL.revokeObjectURL(downloadUrl)
      success('Export complete', `${type} findings exported as ${format.toUpperCase()}`)
    } catch (err) {
      console.error('Export failed:', err)
      showError('Export failed', 'Unable to export findings. Please try again.')
    } finally {
      setExporting(null)
    }
  }

  useEffect(() => {
    const fetchFindings = async () => {
      setLoading(true)
      setError(null)
      try {
        switch (type) {
          case 'security':
            const security = await api.getSecurityFindings(undefined, undefined, false)
            setSecurityFindings(security)
            break
          case 'files':
            const files = await api.getHighRiskFiles()
            setFileFindings(files)
            break
          case 'users':
            const users = await api.getInactiveUsers()
            setUserFindings(users)
            break
          case 'oauth':
            const oauth = await api.getRiskyOAuthApps()
            setOAuthFindings(oauth)
            break
        }
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to load findings')
      } finally {
        setLoading(false)
      }
    }

    fetchFindings()
    // Reset filters when tab changes
    setSearchQuery('')
    setSeverityFilter('all')
    setSortField(type === 'security' ? 'severity' : 'risk_score')
    setSortDirection('desc')
  }, [type])

  // Filtered and sorted security findings
  const filteredSecurityFindings = useMemo(() => {
    let filtered = [...securityFindings]

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(
        f =>
          f.title.toLowerCase().includes(query) ||
          f.description?.toLowerCase().includes(query) ||
          f.check_id?.toLowerCase().includes(query)
      )
    }

    // Apply severity filter
    if (severityFilter !== 'all') {
      filtered = filtered.filter(f => f.severity === severityFilter)
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let comparison = 0
      if (sortField === 'severity') {
        comparison = (SEVERITY_ORDER[a.severity] || 0) - (SEVERITY_ORDER[b.severity] || 0)
      } else if (sortField === 'title') {
        comparison = a.title.localeCompare(b.title)
      } else if (sortField === 'date') {
        comparison = new Date(a.detected_at || 0).getTime() - new Date(b.detected_at || 0).getTime()
      }
      return sortDirection === 'desc' ? -comparison : comparison
    })

    return filtered
  }, [securityFindings, searchQuery, severityFilter, sortField, sortDirection])

  // Filtered and sorted file findings
  const filteredFileFindings = useMemo(() => {
    let filtered = [...fileFindings]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(
        f =>
          f.file_name.toLowerCase().includes(query) ||
          f.owner_email?.toLowerCase().includes(query)
      )
    }

    filtered.sort((a, b) => {
      let comparison = 0
      if (sortField === 'risk_score') {
        comparison = (a.risk_score || 0) - (b.risk_score || 0)
      } else if (sortField === 'file_name') {
        comparison = a.file_name.localeCompare(b.file_name)
      } else if (sortField === 'owner') {
        comparison = (a.owner_email || '').localeCompare(b.owner_email || '')
      }
      return sortDirection === 'desc' ? -comparison : comparison
    })

    return filtered
  }, [fileFindings, searchQuery, sortField, sortDirection])

  // Filtered and sorted user findings
  const filteredUserFindings = useMemo(() => {
    let filtered = [...userFindings]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(
        f =>
          f.email.toLowerCase().includes(query) ||
          f.full_name?.toLowerCase().includes(query)
      )
    }

    filtered.sort((a, b) => {
      let comparison = 0
      if (sortField === 'risk_score') {
        comparison = (a.risk_score || 0) - (b.risk_score || 0)
      } else if (sortField === 'days_inactive') {
        comparison = (a.days_since_last_login || 0) - (b.days_since_last_login || 0)
      } else if (sortField === 'email') {
        comparison = a.email.localeCompare(b.email)
      }
      return sortDirection === 'desc' ? -comparison : comparison
    })

    return filtered
  }, [userFindings, searchQuery, sortField, sortDirection])

  // Filtered and sorted OAuth findings
  const filteredOAuthFindings = useMemo(() => {
    let filtered = [...oauthFindings]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(
        f =>
          f.display_text?.toLowerCase().includes(query) ||
          f.client_id?.toLowerCase().includes(query)
      )
    }

    filtered.sort((a, b) => {
      let comparison = 0
      if (sortField === 'risk_score') {
        comparison = (a.risk_score || 0) - (b.risk_score || 0)
      } else if (sortField === 'user_count') {
        comparison = (a.user_count || 0) - (b.user_count || 0)
      } else if (sortField === 'name') {
        comparison = (a.display_text || a.client_id || '').localeCompare(b.display_text || b.client_id || '')
      }
      return sortDirection === 'desc' ? -comparison : comparison
    })

    return filtered
  }, [oauthFindings, searchQuery, sortField, sortDirection])

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDirection('desc')
    }
  }

  const SortIcon = ({ field }: { field: string }) => {
    if (sortField !== field) {
      return <ArrowUpDown className="h-3 w-3 ml-1 opacity-50" />
    }
    return sortDirection === 'desc' ? (
      <ChevronDown className="h-3 w-3 ml-1" />
    ) : (
      <ChevronUp className="h-3 w-3 ml-1" />
    )
  }

  const tabs = [
    { key: 'security', label: 'Security Posture' },
    { key: 'files', label: 'High-Risk Files' },
    { key: 'users', label: 'Inactive Users' },
    { key: 'oauth', label: 'Risky OAuth Apps' },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Findings</h1>
          <p className="text-muted-foreground">
            Security findings from your scans
          </p>
        </div>
        <div className="flex items-center space-x-2 print:hidden">
          <button
            onClick={handleExportPDF}
            className="flex items-center space-x-1 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            <FileText className="h-4 w-4" />
            <span>PDF</span>
          </button>
          <button
            onClick={() => handleExport('csv')}
            disabled={exporting !== null}
            className="flex items-center space-x-1 rounded-md border px-3 py-2 text-sm font-medium hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {exporting === 'csv' ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Download className="h-4 w-4" />
            )}
            <span>CSV</span>
          </button>
          <button
            onClick={() => handleExport('json')}
            disabled={exporting !== null}
            className="flex items-center space-x-1 rounded-md border px-3 py-2 text-sm font-medium hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {exporting === 'json' ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Download className="h-4 w-4" />
            )}
            <span>JSON</span>
          </button>
        </div>
      </div>

      <div className="flex space-x-2 border-b">
        {tabs.map((tab) => (
          <a
            key={tab.key}
            href={`/dashboard/findings?type=${tab.key}`}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
              type === tab.key
                ? 'border-primary text-primary'
                : 'border-transparent text-muted-foreground hover:text-foreground'
            }`}
          >
            {tab.label}
          </a>
        ))}
      </div>

      {/* Filter and Search Controls */}
      <div className="flex flex-wrap items-center gap-4">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder={
              type === 'security' ? 'Search by title, description, or check ID...' :
              type === 'files' ? 'Search by file name or owner...' :
              type === 'users' ? 'Search by name or email...' :
              'Search by app name or client ID...'
            }
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-md border pl-9 pr-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>

        {type === 'security' && (
          <div className="flex items-center space-x-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-md border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        )}

        <div className="flex items-center space-x-2">
          <span className="text-sm text-muted-foreground">Sort by:</span>
          <select
            value={sortField}
            onChange={(e) => setSortField(e.target.value)}
            className="rounded-md border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
          >
            {type === 'security' && (
              <>
                <option value="severity">Severity</option>
                <option value="title">Title</option>
                <option value="date">Date</option>
              </>
            )}
            {type === 'files' && (
              <>
                <option value="risk_score">Risk Score</option>
                <option value="file_name">File Name</option>
                <option value="owner">Owner</option>
              </>
            )}
            {type === 'users' && (
              <>
                <option value="risk_score">Risk Score</option>
                <option value="days_inactive">Days Inactive</option>
                <option value="email">Email</option>
              </>
            )}
            {type === 'oauth' && (
              <>
                <option value="risk_score">Risk Score</option>
                <option value="user_count">User Count</option>
                <option value="name">App Name</option>
              </>
            )}
          </select>
          <button
            onClick={() => setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')}
            className="rounded-md border p-2 hover:bg-gray-50"
            title={sortDirection === 'desc' ? 'Sort descending' : 'Sort ascending'}
          >
            {sortDirection === 'desc' ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronUp className="h-4 w-4" />
            )}
          </button>
        </div>
      </div>

      {loading ? (
        <Card>
          <CardHeader>
            <CardTitle>Loading...</CardTitle>
          </CardHeader>
          <CardContent>
            {(type === 'security' || type === 'oauth') ? (
              <CardListSkeleton count={5} />
            ) : (
              <TableSkeleton rows={8} cols={5} />
            )}
          </CardContent>
        </Card>
      ) : error ? (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-700">{error}</p>
        </div>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>
              {type === 'security' && (
                <>
                  Security Findings ({filteredSecurityFindings.length}
                  {filteredSecurityFindings.length !== securityFindings.length && (
                    <span className="text-muted-foreground font-normal"> of {securityFindings.length}</span>
                  )})
                </>
              )}
              {type === 'files' && (
                <>
                  High-Risk Files ({filteredFileFindings.length}
                  {filteredFileFindings.length !== fileFindings.length && (
                    <span className="text-muted-foreground font-normal"> of {fileFindings.length}</span>
                  )})
                </>
              )}
              {type === 'users' && (
                <>
                  Inactive Users ({filteredUserFindings.length}
                  {filteredUserFindings.length !== userFindings.length && (
                    <span className="text-muted-foreground font-normal"> of {userFindings.length}</span>
                  )})
                </>
              )}
              {type === 'oauth' && (
                <>
                  Risky OAuth Apps ({filteredOAuthFindings.length}
                  {filteredOAuthFindings.length !== oauthFindings.length && (
                    <span className="text-muted-foreground font-normal"> of {oauthFindings.length}</span>
                  )})
                </>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {type === 'security' && (
              <SecurityFindingsList findings={filteredSecurityFindings} />
            )}
            {type === 'files' && (
              <FileFindingsList findings={filteredFileFindings} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
            )}
            {type === 'users' && (
              <UserFindingsList findings={filteredUserFindings} onSort={handleSort} sortField={sortField} sortDirection={sortDirection} />
            )}
            {type === 'oauth' && (
              <OAuthFindingsList findings={filteredOAuthFindings} />
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function SecurityFindingsList({ findings }: { findings: SecurityFinding[] }) {
  if (findings.length === 0) {
    return <p className="text-muted-foreground">No security findings</p>
  }

  return (
    <div className="space-y-4">
      {findings.map((finding) => (
        <Link
          key={finding.id}
          href={`/dashboard/findings/security/${finding.id}`}
          className="block rounded-lg border p-4 hover:border-primary hover:bg-gray-50 transition-colors"
        >
          <div className="flex items-start justify-between">
            <div className="space-y-1 flex-1">
              <div className="flex items-center space-x-2">
                <span className={`inline-flex rounded-full px-2 py-1 text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                  {finding.severity}
                </span>
                <span className="text-xs text-muted-foreground">{finding.check_id}</span>
              </div>
              <h3 className="font-medium">{finding.title}</h3>
              <p className="text-sm text-muted-foreground line-clamp-2">{finding.description}</p>
            </div>
            <ChevronRight className="h-5 w-5 text-muted-foreground flex-shrink-0 ml-4" />
          </div>
          {finding.remediation && (
            <div className="mt-3 rounded-md bg-blue-50 p-3">
              <p className="text-sm font-medium text-blue-800">Remediation</p>
              <p className="mt-1 text-sm text-blue-700 line-clamp-2">{finding.remediation}</p>
            </div>
          )}
        </Link>
      ))}
    </div>
  )
}

interface SortableListProps {
  onSort: (field: string) => void
  sortField: string
  sortDirection: SortDirection
}

function FileFindingsList({ findings, onSort, sortField, sortDirection }: { findings: FileFinding[] } & SortableListProps) {
  if (findings.length === 0) {
    return <p className="text-muted-foreground">No high-risk files found</p>
  }

  const SortableHeader = ({ field, children }: { field: string; children: React.ReactNode }) => (
    <th
      className="pb-3 font-medium cursor-pointer hover:text-primary select-none"
      onClick={() => onSort(field)}
    >
      <div className="flex items-center">
        {children}
        {sortField === field ? (
          sortDirection === 'desc' ? (
            <ChevronDown className="h-3 w-3 ml-1" />
          ) : (
            <ChevronUp className="h-3 w-3 ml-1" />
          )
        ) : (
          <ArrowUpDown className="h-3 w-3 ml-1 opacity-50" />
        )}
      </div>
    </th>
  )

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b text-left">
            <SortableHeader field="file_name">File Name</SortableHeader>
            <SortableHeader field="owner">Owner</SortableHeader>
            <SortableHeader field="risk_score">Risk Score</SortableHeader>
            <th className="pb-3 font-medium">Sharing</th>
            <th className="pb-3 font-medium">PII</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((file) => (
            <tr key={file.id} className="border-b hover:bg-gray-50 cursor-pointer" onClick={() => window.location.href = `/dashboard/findings/files/${file.id}`}>
              <td className="py-3">
                <div>
                  <p className="font-medium truncate max-w-xs">{file.file_name}</p>
                  <p className="text-xs text-muted-foreground">{file.mime_type}</p>
                </div>
              </td>
              <td className="py-3 text-sm">{file.owner_email}</td>
              <td className="py-3">
                <span className={`font-medium ${file.risk_score >= 70 ? 'text-red-600' : file.risk_score >= 50 ? 'text-orange-600' : ''}`}>
                  {file.risk_score}
                </span>
              </td>
              <td className="py-3">
                {file.is_public && <Badge variant="destructive">Public</Badge>}
                {file.is_shared_externally && !file.is_public && <Badge variant="warning">External</Badge>}
              </td>
              <td className="py-3">
                {file.pii_detected && <Badge variant="destructive">Yes</Badge>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function UserFindingsList({ findings, onSort, sortField, sortDirection }: { findings: UserFinding[] } & SortableListProps) {
  if (findings.length === 0) {
    return <p className="text-muted-foreground">No inactive users found</p>
  }

  const SortableHeader = ({ field, children }: { field: string; children: React.ReactNode }) => (
    <th
      className="pb-3 font-medium cursor-pointer hover:text-primary select-none"
      onClick={() => onSort(field)}
    >
      <div className="flex items-center">
        {children}
        {sortField === field ? (
          sortDirection === 'desc' ? (
            <ChevronDown className="h-3 w-3 ml-1" />
          ) : (
            <ChevronUp className="h-3 w-3 ml-1" />
          )
        ) : (
          <ArrowUpDown className="h-3 w-3 ml-1 opacity-50" />
        )}
      </div>
    </th>
  )

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b text-left">
            <SortableHeader field="email">User</SortableHeader>
            <th className="pb-3 font-medium">Last Login</th>
            <SortableHeader field="days_inactive">Days Inactive</SortableHeader>
            <th className="pb-3 font-medium">2FA</th>
            <th className="pb-3 font-medium">Admin</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((user) => (
            <tr key={user.id} className="border-b hover:bg-gray-50 cursor-pointer" onClick={() => window.location.href = `/dashboard/findings/users/${user.id}`}>
              <td className="py-3">
                <div>
                  <p className="font-medium">{user.full_name || user.email}</p>
                  <p className="text-xs text-muted-foreground">{user.email}</p>
                </div>
              </td>
              <td className="py-3 text-sm">
                {user.last_login_time ? formatDate(user.last_login_time) : 'Never'}
              </td>
              <td className="py-3">
                <span className="font-medium text-orange-600">
                  {user.days_since_last_login || 'N/A'}
                </span>
              </td>
              <td className="py-3">
                {user.two_factor_enabled ? (
                  <Badge variant="success">Enabled</Badge>
                ) : (
                  <Badge variant="destructive">Disabled</Badge>
                )}
              </td>
              <td className="py-3">
                {user.is_admin && <Badge>Admin</Badge>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function OAuthFindingsList({ findings }: { findings: OAuthFinding[] }) {
  if (findings.length === 0) {
    return <p className="text-muted-foreground">No risky OAuth apps found</p>
  }

  return (
    <div className="space-y-4">
      {findings.map((app) => (
        <Link
          key={app.id}
          href={`/dashboard/findings/oauth/${app.id}`}
          className="block rounded-lg border p-4 hover:border-primary hover:bg-gray-50 transition-colors"
        >
          <div className="flex items-start justify-between">
            <div className="space-y-1 flex-1">
              <div className="flex items-center space-x-2">
                <span className={`font-medium ${app.risk_score >= 70 ? 'text-red-600' : app.risk_score >= 50 ? 'text-orange-600' : ''}`}>
                  Risk: {app.risk_score}
                </span>
                {!app.is_verified && <Badge variant="warning">Unverified</Badge>}
              </div>
              <h3 className="font-medium">{app.display_text || app.client_id}</h3>
              <p className="text-sm text-muted-foreground">
                Used by {app.user_count} user(s)
              </p>
            </div>
            <ChevronRight className="h-5 w-5 text-muted-foreground flex-shrink-0 ml-4" />
          </div>
          {app.scopes && app.scopes.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-medium text-muted-foreground">Scopes:</p>
              <div className="mt-1 flex flex-wrap gap-1">
                {app.scopes.slice(0, 5).map((scope) => (
                  <span key={scope} className="rounded bg-gray-100 px-2 py-1 text-xs">
                    {scope.split('/').pop()}
                  </span>
                ))}
                {app.scopes.length > 5 && (
                  <span className="rounded bg-gray-100 px-2 py-1 text-xs">
                    +{app.scopes.length - 5} more
                  </span>
                )}
              </div>
            </div>
          )}
        </Link>
      ))}
    </div>
  )
}
