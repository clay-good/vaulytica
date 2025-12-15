'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { api } from '@/lib/api'
import { SecurityFinding, FileFinding, UserFinding, OAuthFinding } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { formatDate, getSeverityColor } from '@/lib/utils'
import {
  ArrowLeft,
  Shield,
  FileWarning,
  Users,
  Key,
  ExternalLink,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Info,
} from 'lucide-react'

type FindingType = 'security' | 'files' | 'users' | 'oauth'

function DetailSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center space-x-4">
        <Skeleton className="h-10 w-10 rounded" />
        <div className="space-y-2">
          <Skeleton className="h-8 w-64" />
          <Skeleton className="h-4 w-48" />
        </div>
      </div>
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-32" />
        </CardHeader>
        <CardContent className="space-y-4">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </CardContent>
      </Card>
    </div>
  )
}

export default function FindingDetailPage() {
  const params = useParams()
  const router = useRouter()
  const type = params.type as FindingType
  const id = parseInt(params.id as string, 10)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [securityFinding, setSecurityFinding] = useState<SecurityFinding | null>(null)
  const [fileFinding, setFileFinding] = useState<FileFinding | null>(null)
  const [userFinding, setUserFinding] = useState<UserFinding | null>(null)
  const [oauthFinding, setOAuthFinding] = useState<OAuthFinding | null>(null)

  useEffect(() => {
    const fetchFinding = async () => {
      setLoading(true)
      setError(null)
      try {
        switch (type) {
          case 'security':
            const security = await api.getSecurityFinding(id)
            setSecurityFinding(security)
            break
          case 'files':
            const file = await api.getFileFinding(id)
            setFileFinding(file)
            break
          case 'users':
            const user = await api.getUserFinding(id)
            setUserFinding(user)
            break
          case 'oauth':
            const oauth = await api.getOAuthFinding(id)
            setOAuthFinding(oauth)
            break
          default:
            setError('Invalid finding type')
        }
      } catch (err: any) {
        if (err.response?.status === 404) {
          setError('Finding not found')
        } else {
          setError(err.response?.data?.detail || 'Failed to load finding')
        }
      } finally {
        setLoading(false)
      }
    }

    if (type && id) {
      fetchFinding()
    }
  }, [type, id])

  const getIcon = () => {
    switch (type) {
      case 'security':
        return <Shield className="h-6 w-6" />
      case 'files':
        return <FileWarning className="h-6 w-6" />
      case 'users':
        return <Users className="h-6 w-6" />
      case 'oauth':
        return <Key className="h-6 w-6" />
      default:
        return <AlertTriangle className="h-6 w-6" />
    }
  }

  const getTitle = () => {
    switch (type) {
      case 'security':
        return 'Security Finding'
      case 'files':
        return 'File Finding'
      case 'users':
        return 'User Finding'
      case 'oauth':
        return 'OAuth Finding'
      default:
        return 'Finding'
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <Link
          href={`/dashboard/findings?type=${type}`}
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Findings
        </Link>
        <DetailSkeleton />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <Link
          href={`/dashboard/findings?type=${type}`}
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Findings
        </Link>
        <div className="rounded-lg border border-red-200 bg-red-50 p-6">
          <p className="text-red-700">{error}</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <Link
        href={`/dashboard/findings?type=${type}`}
        className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Back to Findings
      </Link>

      <div className="flex items-start space-x-4">
        <div className="rounded-lg bg-gray-100 p-3">
          {getIcon()}
        </div>
        <div>
          <h1 className="text-2xl font-bold">{getTitle()} #{id}</h1>
          <p className="text-muted-foreground">
            Detected on {formatDate(
              securityFinding?.detected_at ||
              fileFinding?.detected_at ||
              userFinding?.detected_at ||
              oauthFinding?.detected_at ||
              ''
            )}
          </p>
        </div>
      </div>

      {type === 'security' && securityFinding && (
        <SecurityFindingDetail finding={securityFinding} />
      )}
      {type === 'files' && fileFinding && (
        <FileFindingDetail finding={fileFinding} />
      )}
      {type === 'users' && userFinding && (
        <UserFindingDetail finding={userFinding} />
      )}
      {type === 'oauth' && oauthFinding && (
        <OAuthFindingDetail finding={oauthFinding} />
      )}
    </div>
  )
}

function SecurityFindingDetail({ finding }: { finding: SecurityFinding }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>{finding.title}</CardTitle>
            <div className="flex items-center space-x-2">
              <span className={`inline-flex rounded-full px-3 py-1 text-sm font-medium ${getSeverityColor(finding.severity)}`}>
                {finding.severity}
              </span>
              {finding.passed ? (
                <Badge variant="success">Passed</Badge>
              ) : (
                <Badge variant="destructive">Failed</Badge>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-1">Check ID</h3>
            <p className="font-mono text-sm">{finding.check_id}</p>
          </div>

          {finding.description && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Description</h3>
              <p>{finding.description}</p>
            </div>
          )}

          <div className="grid gap-4 md:grid-cols-2">
            {finding.current_value && (
              <div>
                <h3 className="text-sm font-medium text-muted-foreground mb-1">Current Value</h3>
                <p className="font-mono text-sm bg-gray-100 p-2 rounded">{finding.current_value}</p>
              </div>
            )}
            {finding.expected_value && (
              <div>
                <h3 className="text-sm font-medium text-muted-foreground mb-1">Expected Value</h3>
                <p className="font-mono text-sm bg-green-50 p-2 rounded text-green-800">{finding.expected_value}</p>
              </div>
            )}
          </div>

          {finding.impact && (
            <div className="rounded-lg border-l-4 border-orange-400 bg-orange-50 p-4">
              <div className="flex items-center">
                <AlertTriangle className="h-5 w-5 text-orange-600 mr-2" />
                <h3 className="font-medium text-orange-800">Impact</h3>
              </div>
              <p className="mt-2 text-orange-700">{finding.impact}</p>
            </div>
          )}

          {finding.remediation && (
            <div className="rounded-lg border-l-4 border-blue-400 bg-blue-50 p-4">
              <div className="flex items-center">
                <Info className="h-5 w-5 text-blue-600 mr-2" />
                <h3 className="font-medium text-blue-800">Remediation</h3>
              </div>
              <p className="mt-2 text-blue-700">{finding.remediation}</p>
            </div>
          )}

          {finding.frameworks && finding.frameworks.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">Compliance Frameworks</h3>
              <div className="flex flex-wrap gap-2">
                {finding.frameworks.map((fw) => (
                  <Badge key={fw} variant="outline">{fw}</Badge>
                ))}
              </div>
            </div>
          )}

          {(finding.resource_type || finding.resource_id) && (
            <div className="border-t pt-4">
              <h3 className="text-sm font-medium text-muted-foreground mb-2">Resource Information</h3>
              <div className="grid gap-2 md:grid-cols-2">
                {finding.resource_type && (
                  <div>
                    <span className="text-sm text-muted-foreground">Type:</span>
                    <span className="ml-2">{finding.resource_type}</span>
                  </div>
                )}
                {finding.resource_id && (
                  <div>
                    <span className="text-sm text-muted-foreground">ID:</span>
                    <span className="ml-2 font-mono text-sm">{finding.resource_id}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function FileFindingDetail({ finding }: { finding: FileFinding }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="truncate">{finding.file_name}</CardTitle>
            <div className="flex items-center space-x-2">
              <span className={`font-medium ${finding.risk_score >= 70 ? 'text-red-600' : finding.risk_score >= 50 ? 'text-orange-600' : 'text-green-600'}`}>
                Risk Score: {finding.risk_score}
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">File ID</h3>
              <p className="font-mono text-sm">{finding.file_id}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">MIME Type</h3>
              <p>{finding.mime_type || 'Unknown'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Owner</h3>
              <p>{finding.owner_email || 'Unknown'}</p>
              {finding.owner_name && <p className="text-sm text-muted-foreground">{finding.owner_name}</p>}
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">File Size</h3>
              <p>{finding.file_size ? `${(finding.file_size / 1024).toFixed(2)} KB` : 'Unknown'}</p>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-2">Sharing Status</h3>
            <div className="flex flex-wrap gap-2">
              {finding.is_public && (
                <Badge variant="destructive">Publicly Accessible</Badge>
              )}
              {finding.is_shared_externally && !finding.is_public && (
                <Badge variant="warning">Shared Externally</Badge>
              )}
              {!finding.is_public && !finding.is_shared_externally && (
                <Badge variant="success">Internal Only</Badge>
              )}
            </div>
          </div>

          {finding.external_domains && finding.external_domains.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">External Domains</h3>
              <div className="flex flex-wrap gap-2">
                {finding.external_domains.map((domain) => (
                  <Badge key={domain} variant="outline">{domain}</Badge>
                ))}
              </div>
            </div>
          )}

          {finding.external_emails && finding.external_emails.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">External Users</h3>
              <ul className="list-disc list-inside text-sm">
                {finding.external_emails.slice(0, 10).map((email) => (
                  <li key={email}>{email}</li>
                ))}
                {finding.external_emails.length > 10 && (
                  <li className="text-muted-foreground">...and {finding.external_emails.length - 10} more</li>
                )}
              </ul>
            </div>
          )}

          {finding.pii_detected && (
            <div className="rounded-lg border-l-4 border-red-400 bg-red-50 p-4">
              <div className="flex items-center">
                <AlertTriangle className="h-5 w-5 text-red-600 mr-2" />
                <h3 className="font-medium text-red-800">PII Detected</h3>
              </div>
              {finding.pii_types && finding.pii_types.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {finding.pii_types.map((pii) => (
                    <Badge key={pii} variant="destructive">{pii}</Badge>
                  ))}
                </div>
              )}
            </div>
          )}

          {finding.web_view_link && (
            <div className="border-t pt-4">
              <a
                href={finding.web_view_link}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center text-primary hover:underline"
              >
                <ExternalLink className="mr-2 h-4 w-4" />
                Open in Google Drive
              </a>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function UserFindingDetail({ finding }: { finding: UserFinding }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>{finding.full_name || finding.email}</CardTitle>
            <div className="flex items-center space-x-2">
              <span className={`font-medium ${finding.risk_score >= 70 ? 'text-red-600' : finding.risk_score >= 50 ? 'text-orange-600' : 'text-green-600'}`}>
                Risk Score: {finding.risk_score}
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Email</h3>
              <p>{finding.email}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">User ID</h3>
              <p className="font-mono text-sm">{finding.user_id}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Org Unit</h3>
              <p>{finding.org_unit_path || 'Root'}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Created</h3>
              <p>{finding.creation_time ? formatDate(finding.creation_time) : 'Unknown'}</p>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-2">Account Status</h3>
            <div className="flex flex-wrap gap-2">
              {finding.is_admin && <Badge variant="default">Administrator</Badge>}
              {finding.is_suspended && <Badge variant="destructive">Suspended</Badge>}
              {finding.is_archived && <Badge variant="secondary">Archived</Badge>}
              {finding.is_inactive && <Badge variant="warning">Inactive</Badge>}
              {!finding.is_suspended && !finding.is_archived && !finding.is_inactive && (
                <Badge variant="success">Active</Badge>
              )}
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Last Login</h3>
              <div className="flex items-center">
                <Clock className="mr-2 h-4 w-4 text-muted-foreground" />
                <span>{finding.last_login_time ? formatDate(finding.last_login_time) : 'Never'}</span>
              </div>
              {finding.days_since_last_login && (
                <p className="text-sm text-orange-600 mt-1">
                  {finding.days_since_last_login} days since last login
                </p>
              )}
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Two-Factor Authentication</h3>
              {finding.two_factor_enabled ? (
                <div className="flex items-center text-green-600">
                  <CheckCircle className="mr-2 h-4 w-4" />
                  Enabled
                </div>
              ) : (
                <div className="flex items-center text-red-600">
                  <XCircle className="mr-2 h-4 w-4" />
                  Not Enabled
                </div>
              )}
            </div>
          </div>

          {finding.risk_factors && finding.risk_factors.length > 0 && (
            <div className="rounded-lg border-l-4 border-orange-400 bg-orange-50 p-4">
              <h3 className="font-medium text-orange-800 mb-2">Risk Factors</h3>
              <ul className="list-disc list-inside text-orange-700">
                {finding.risk_factors.map((factor, index) => (
                  <li key={index}>{factor}</li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function OAuthFindingDetail({ finding }: { finding: OAuthFinding }) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>{finding.display_text || finding.client_id}</CardTitle>
            <div className="flex items-center space-x-2">
              <span className={`font-medium ${finding.risk_score >= 70 ? 'text-red-600' : finding.risk_score >= 50 ? 'text-orange-600' : 'text-green-600'}`}>
                Risk Score: {finding.risk_score}
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">Client ID</h3>
              <p className="font-mono text-sm break-all">{finding.client_id}</p>
            </div>
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-1">User Count</h3>
              <p>{finding.user_count} user(s)</p>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-medium text-muted-foreground mb-2">App Status</h3>
            <div className="flex flex-wrap gap-2">
              {finding.is_verified ? (
                <Badge variant="success">Verified</Badge>
              ) : (
                <Badge variant="warning">Unverified</Badge>
              )}
              {finding.is_google_app && <Badge variant="outline">Google App</Badge>}
              {finding.is_internal && <Badge variant="outline">Internal</Badge>}
            </div>
          </div>

          {finding.scopes && finding.scopes.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">
                Requested Scopes ({finding.scopes.length})
              </h3>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {finding.scopes.map((scope) => (
                  <div key={scope} className="rounded bg-gray-100 px-2 py-1 text-xs font-mono">
                    {scope}
                  </div>
                ))}
              </div>
            </div>
          )}

          {finding.users && finding.users.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-muted-foreground mb-2">
                Authorized Users ({finding.users.length})
              </h3>
              <ul className="list-disc list-inside text-sm max-h-48 overflow-y-auto">
                {finding.users.slice(0, 20).map((user) => (
                  <li key={user}>{user}</li>
                ))}
                {finding.users.length > 20 && (
                  <li className="text-muted-foreground">...and {finding.users.length - 20} more</li>
                )}
              </ul>
            </div>
          )}

          {finding.risk_factors && finding.risk_factors.length > 0 && (
            <div className="rounded-lg border-l-4 border-orange-400 bg-orange-50 p-4">
              <h3 className="font-medium text-orange-800 mb-2">Risk Factors</h3>
              <ul className="list-disc list-inside text-orange-700">
                {finding.risk_factors.map((factor, index) => (
                  <li key={index}>{factor}</li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
