'use client'

import { useEffect, useState, useCallback } from 'react'
import { api } from '@/lib/api'
import { User, Domain, CredentialsStatus } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { FormField, Input } from '@/components/ui/form-input'
import { useToast } from '@/components/ui/toast'
import { formatDate } from '@/lib/utils'
import { RefreshCw, AlertTriangle, CheckCircle, Clock, Key } from 'lucide-react'

export default function SettingsPage() {
  const { toast } = useToast()
  const [user, setUser] = useState<User | null>(null)
  const [domains, setDomains] = useState<Domain[]>([])
  const [loading, setLoading] = useState(true)

  // Credential rotation state
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null)
  const [credentialsStatus, setCredentialsStatus] = useState<CredentialsStatus | null>(null)
  const [loadingStatus, setLoadingStatus] = useState(false)
  const [showRotateModal, setShowRotateModal] = useState(false)
  const [newCredentialsPath, setNewCredentialsPath] = useState('')
  const [rotating, setRotating] = useState(false)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [userData, domainsData] = await Promise.all([
          api.getCurrentUser(),
          api.getDomains(),
        ])
        setUser(userData)
        setDomains(domainsData)
      } catch (err) {
        console.error('Failed to load settings:', err)
        toast.error('Failed to load settings')
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [])

  const fetchCredentialsStatus = useCallback(async (domainName: string) => {
    setLoadingStatus(true)
    setSelectedDomain(domainName)
    try {
      const status = await api.getCredentialsStatus(domainName)
      setCredentialsStatus(status)
    } catch (err) {
      toast.error('Failed to fetch credentials status')
      setCredentialsStatus(null)
    } finally {
      setLoadingStatus(false)
    }
  }, [toast])

  const handleRotate = async () => {
    if (!selectedDomain || !newCredentialsPath.trim()) {
      toast.error('Please enter a credentials path')
      return
    }

    setRotating(true)
    try {
      const result = await api.rotateCredentials(selectedDomain, newCredentialsPath.trim())
      toast.success(result.message)
      setShowRotateModal(false)
      setNewCredentialsPath('')
      // Refresh status
      await fetchCredentialsStatus(selectedDomain)
      // Refresh domains list
      const domainsData = await api.getDomains()
      setDomains(domainsData)
    } catch (err) {
      toast.error('Failed to rotate credentials')
    } finally {
      setRotating(false)
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-500 dark:text-gray-400">Loading...</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Manage your account and domain access
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Account Information</CardTitle>
            <CardDescription>Your user account details</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Email</label>
              <p className="mt-1 text-gray-900 dark:text-white">{user?.email}</p>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Full Name</label>
              <p className="mt-1 text-gray-900 dark:text-white">{user?.full_name || 'Not set'}</p>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Account Type</label>
              <p className="mt-1">
                {user?.is_superuser ? (
                  <Badge>Administrator</Badge>
                ) : (
                  <Badge variant="secondary">Standard User</Badge>
                )}
              </p>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500 dark:text-gray-400">Member Since</label>
              <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">
                {user?.created_at ? formatDate(user.created_at) : 'Unknown'}
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Domain Access</CardTitle>
            <CardDescription>Google Workspace domains you can access</CardDescription>
          </CardHeader>
          <CardContent>
            {user?.is_superuser ? (
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                As an administrator, you have access to all domains.
              </p>
            ) : user?.domains && user.domains.length > 0 ? (
              <div className="space-y-2">
                {user.domains.map((domain) => (
                  <div
                    key={domain.domain}
                    className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-700 p-3"
                  >
                    <span className="text-gray-900 dark:text-white">{domain.domain}</span>
                    <Badge variant="secondary">{domain.role}</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500 dark:text-gray-400">
                No domain access configured. Contact an administrator.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Registered Domains with Credential Management */}
      <Card>
        <CardHeader>
          <CardTitle>Registered Domains</CardTitle>
          <CardDescription>All domains configured in the system with credential status</CardDescription>
        </CardHeader>
        <CardContent>
          {domains.length === 0 ? (
            <p className="text-gray-500 dark:text-gray-400">No domains registered</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700 text-left">
                    <th className="pb-3 font-medium text-gray-600 dark:text-gray-300">Domain</th>
                    <th className="pb-3 font-medium text-gray-600 dark:text-gray-300">Display Name</th>
                    <th className="pb-3 font-medium text-gray-600 dark:text-gray-300">Status</th>
                    <th className="pb-3 font-medium text-gray-600 dark:text-gray-300">Credentials</th>
                    <th className="pb-3 font-medium text-gray-600 dark:text-gray-300">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {domains.map((domain) => (
                    <tr key={domain.id} className="border-b border-gray-200 dark:border-gray-700">
                      <td className="py-3 font-medium text-gray-900 dark:text-white">{domain.name}</td>
                      <td className="py-3 text-gray-600 dark:text-gray-300">{domain.display_name || '-'}</td>
                      <td className="py-3">
                        <Badge variant={domain.is_active ? 'success' : 'secondary'}>
                          {domain.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </td>
                      <td className="py-3">
                        {domain.credentials_rotated_at ? (
                          <span className="text-sm text-gray-600 dark:text-gray-300">
                            Rotated: {formatDate(domain.credentials_rotated_at)}
                          </span>
                        ) : (
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            Never rotated
                          </span>
                        )}
                      </td>
                      <td className="py-3">
                        {user?.is_superuser && (
                          <button
                            onClick={() => fetchCredentialsStatus(domain.name)}
                            className="text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 dark:hover:text-indigo-300 text-sm font-medium flex items-center gap-1"
                          >
                            <Key className="h-4 w-4" />
                            Manage
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Credentials Status Panel */}
      {selectedDomain && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Key className="h-5 w-5" />
              Credentials: {selectedDomain}
            </CardTitle>
            <CardDescription>Service account credentials status and rotation</CardDescription>
          </CardHeader>
          <CardContent>
            {loadingStatus ? (
              <p className="text-gray-500 dark:text-gray-400">Loading credentials status...</p>
            ) : credentialsStatus ? (
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="p-4 rounded-lg bg-gray-50 dark:bg-gray-800">
                    <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 mb-1">
                      <Clock className="h-4 w-4" />
                      <span className="text-sm font-medium">Days Since Rotation</span>
                    </div>
                    <p className="text-2xl font-bold text-gray-900 dark:text-white">
                      {credentialsStatus.days_since_rotation}
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-gray-50 dark:bg-gray-800">
                    <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 mb-1">
                      <Clock className="h-4 w-4" />
                      <span className="text-sm font-medium">Last Rotated</span>
                    </div>
                    <p className="text-lg font-medium text-gray-900 dark:text-white">
                      {credentialsStatus.last_rotated
                        ? formatDate(credentialsStatus.last_rotated)
                        : 'Never'}
                    </p>
                  </div>

                  <div className="p-4 rounded-lg bg-gray-50 dark:bg-gray-800">
                    <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400 mb-1">
                      {credentialsStatus.rotation_recommended ? (
                        <AlertTriangle className="h-4 w-4 text-yellow-500" />
                      ) : (
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      )}
                      <span className="text-sm font-medium">Status</span>
                    </div>
                    <p className={`text-lg font-medium ${
                      credentialsStatus.rotation_recommended
                        ? 'text-yellow-600 dark:text-yellow-400'
                        : 'text-green-600 dark:text-green-400'
                    }`}>
                      {credentialsStatus.rotation_recommended
                        ? 'Rotation Recommended'
                        : 'Up to Date'}
                    </p>
                  </div>
                </div>

                {credentialsStatus.rotation_recommended && (
                  <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className="h-5 w-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-medium text-yellow-800 dark:text-yellow-200">
                          Credentials rotation recommended
                        </p>
                        <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                          It has been more than {credentialsStatus.recommendation_threshold_days} days
                          since credentials were last rotated. Consider rotating them for security.
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                <div className="flex gap-3">
                  <button
                    onClick={() => setShowRotateModal(true)}
                    className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                  >
                    <RefreshCw className="h-4 w-4" />
                    Rotate Credentials
                  </button>
                  <button
                    onClick={() => {
                      setSelectedDomain(null)
                      setCredentialsStatus(null)
                    }}
                    className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 text-gray-700 dark:text-gray-300 transition-colors"
                  >
                    Close
                  </button>
                </div>
              </div>
            ) : (
              <p className="text-gray-500 dark:text-gray-400">
                Failed to load credentials status
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Rotate Credentials Modal */}
      {showRotateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full mx-4 p-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
              Rotate Credentials
            </h2>
            <p className="text-gray-600 dark:text-gray-300 mb-4">
              Enter the path to the new service account credentials file for{' '}
              <strong>{selectedDomain}</strong>.
            </p>

            <FormField label="New Credentials Path" required>
              <Input
                type="text"
                value={newCredentialsPath}
                onChange={(e) => setNewCredentialsPath(e.target.value)}
                placeholder="/path/to/service-account.json"
              />
            </FormField>

            <div className="p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg mt-4">
              <p className="text-sm text-yellow-700 dark:text-yellow-300">
                <strong>Warning:</strong> Ensure the new credentials file is valid and has the
                required permissions before rotating. Invalid credentials will prevent scanning.
              </p>
            </div>

            <div className="flex justify-end gap-3 mt-6">
              <button
                onClick={() => {
                  setShowRotateModal(false)
                  setNewCredentialsPath('')
                }}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 text-gray-700 dark:text-gray-300 transition-colors"
                disabled={rotating}
              >
                Cancel
              </button>
              <button
                onClick={handleRotate}
                disabled={rotating || !newCredentialsPath.trim()}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {rotating ? (
                  <>
                    <RefreshCw className="h-4 w-4 animate-spin" />
                    Rotating...
                  </>
                ) : (
                  <>
                    <RefreshCw className="h-4 w-4" />
                    Rotate
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>API Information</CardTitle>
          <CardDescription>Backend API details</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <div className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-700 p-3">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">API URL</span>
            <code className="text-sm text-gray-500 dark:text-gray-400">
              {process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}
            </code>
          </div>
          <div className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-700 p-3">
            <span className="text-sm font-medium text-gray-700 dark:text-gray-300">API Documentation</span>
            <a
              href={`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/docs`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-sm text-indigo-600 dark:text-indigo-400 hover:underline"
            >
              View Swagger Docs
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
