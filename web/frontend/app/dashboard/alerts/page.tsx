'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { AlertRule, AlertRuleCreate, Domain, ConditionType } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/toast'
import { FormField, Input, Select, Checkbox, TextArea } from '@/components/ui/form-input'
import { formatDate } from '@/lib/utils'
import { Bell, Trash2, Plus, Loader2, Play, Pause, Mail, Globe } from 'lucide-react'
import { usePermissions } from '@/contexts/PermissionsContext'

export default function AlertsPage() {
  const [loading, setLoading] = useState(true)
  const [alerts, setAlerts] = useState<AlertRule[]>([])
  const [domains, setDomains] = useState<Domain[]>([])
  const [conditionTypes, setConditionTypes] = useState<ConditionType[]>([])
  const [error, setError] = useState<string | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [togglingId, setTogglingId] = useState<number | null>(null)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const { success, error: showError } = useToast()
  const { canEdit, permissions } = usePermissions()

  // Check if user can manage alerts on any domain
  const canManageAlerts = permissions?.is_superuser || (permissions?.editable_domains.length ?? 0) > 0

  // Filter domains to only show ones user can edit
  const editableDomains = domains.filter(d => canEdit(d.name))

  // Form state
  const [formData, setFormData] = useState<AlertRuleCreate>({
    name: '',
    description: '',
    domain_name: '',
    condition_type: 'scan_completed',
    condition_value: {},
    notification_channels: ['email'],
    notification_config: { emails: [] },
    is_active: true,
  })
  const [emailInput, setEmailInput] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')

  const fetchData = async () => {
    try {
      const [alertsData, domainsData, typesData] = await Promise.all([
        api.getAlertRules().then(r => r.items),
        api.getDomains(),
        api.getConditionTypes(),
      ])
      setAlerts(alertsData)
      setDomains(domainsData)
      setConditionTypes(typesData)
      if (domainsData.length > 0 && !formData.domain_name) {
        setFormData(prev => ({ ...prev, domain_name: domainsData[0].name }))
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load alerts')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleToggle = async (alert: AlertRule) => {
    setTogglingId(alert.id)
    try {
      await api.updateAlertRule(alert.id, { is_active: !alert.is_active })
      await fetchData()
      success(
        alert.is_active ? 'Alert paused' : 'Alert activated',
        alert.is_active ? 'The alert rule has been paused.' : 'The alert rule is now active.'
      )
    } catch (err: any) {
      showError('Failed to update alert', err.response?.data?.detail || 'Please try again.')
    } finally {
      setTogglingId(null)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this alert rule?')) return
    setDeletingId(id)
    try {
      await api.deleteAlertRule(id)
      await fetchData()
      success('Alert deleted', 'The alert rule has been removed.')
    } catch (err: any) {
      showError('Failed to delete alert', err.response?.data?.detail || 'Please try again.')
    } finally {
      setDeletingId(null)
    }
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.name.trim()) {
      showError('Validation error', 'Please enter a name for the alert.')
      return
    }
    if (!formData.domain_name) {
      showError('Validation error', 'Please select a domain.')
      return
    }

    // Build notification config
    const config: Record<string, any> = {}
    if (formData.notification_channels?.includes('email') && emailInput.trim()) {
      config.emails = emailInput.split(',').map(e => e.trim()).filter(e => e)
    }
    if (formData.notification_channels?.includes('webhook') && webhookUrl.trim()) {
      config.webhook_url = webhookUrl.trim()
    }

    setCreating(true)
    try {
      await api.createAlertRule({
        ...formData,
        notification_config: config,
      })
      setShowCreateForm(false)
      setFormData({
        name: '',
        description: '',
        domain_name: editableDomains[0]?.name || '',
        condition_type: 'scan_completed',
        condition_value: {},
        notification_channels: ['email'],
        notification_config: {},
        is_active: true,
      })
      setEmailInput('')
      setWebhookUrl('')
      await fetchData()
      success('Alert created', `"${formData.name}" has been created successfully.`)
    } catch (err: any) {
      showError('Failed to create alert', err.response?.data?.detail || 'Please try again.')
    } finally {
      setCreating(false)
    }
  }

  const getConditionDescription = (type: string) => {
    const ct = conditionTypes.find(c => c.type === type)
    return ct?.description || type
  }

  const handleChannelToggle = (channel: string) => {
    const channels = formData.notification_channels || []
    if (channels.includes(channel)) {
      setFormData({
        ...formData,
        notification_channels: channels.filter(c => c !== channel),
      })
    } else {
      setFormData({
        ...formData,
        notification_channels: [...channels, channel],
      })
    }
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="h-8 w-32 bg-gray-200 rounded animate-pulse" />
            <div className="h-4 w-64 bg-gray-100 rounded animate-pulse mt-2" />
          </div>
        </div>
        <Card>
          <CardHeader>
            <div className="h-6 w-40 bg-gray-200 rounded animate-pulse" />
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[1, 2, 3].map(i => (
                <div key={i} className="h-24 bg-gray-100 rounded animate-pulse" />
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Alert Rules</h1>
          <p className="text-muted-foreground">
            Configure notifications for security events
          </p>
        </div>
        {canManageAlerts && (
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-4 w-4" />
            <span>New Alert</span>
          </button>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-700">{error}</p>
          <button
            onClick={() => setError(null)}
            className="mt-2 text-sm text-red-600 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {showCreateForm && (
        <Card>
          <CardHeader>
            <CardTitle>Create Alert Rule</CardTitle>
            <CardDescription>Set up notifications for specific security events</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <FormField label="Name" required>
                  <Input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    placeholder="High Risk Files Alert"
                  />
                </FormField>
                <FormField label="Domain" required>
                  <Select
                    value={formData.domain_name}
                    onChange={(e) => setFormData({ ...formData, domain_name: e.target.value })}
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
                <FormField label="Condition Type" required>
                  <Select
                    value={formData.condition_type}
                    onChange={(e) => setFormData({ ...formData, condition_type: e.target.value })}
                  >
                    {conditionTypes.map((ct) => (
                      <option key={ct.type} value={ct.type}>
                        {ct.description}
                      </option>
                    ))}
                  </Select>
                </FormField>
                <FormField label="Description">
                  <Input
                    type="text"
                    value={formData.description || ''}
                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                    placeholder="Optional description"
                  />
                </FormField>
              </div>

              {/* Condition Value based on type */}
              {(formData.condition_type === 'high_risk_file' || formData.condition_type === 'risky_oauth') && (
                <FormField label="Risk Score Threshold">
                  <Input
                    type="number"
                    min={0}
                    max={100}
                    value={formData.condition_value?.threshold || 75}
                    onChange={(e) => setFormData({
                      ...formData,
                      condition_value: { ...formData.condition_value, threshold: parseInt(e.target.value) || 75 },
                    })}
                    placeholder="75"
                  />
                </FormField>
              )}
              {formData.condition_type === 'inactive_user' && (
                <FormField label="Days Inactive">
                  <Input
                    type="number"
                    min={1}
                    value={formData.condition_value?.days || 90}
                    onChange={(e) => setFormData({
                      ...formData,
                      condition_value: { ...formData.condition_value, days: parseInt(e.target.value) || 90 },
                    })}
                    placeholder="90"
                  />
                </FormField>
              )}
              {formData.condition_type === 'security_finding' && (
                <FormField label="Minimum Severity">
                  <Select
                    value={formData.condition_value?.severity || 'high'}
                    onChange={(e) => setFormData({
                      ...formData,
                      condition_value: { ...formData.condition_value, severity: e.target.value },
                    })}
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </Select>
                </FormField>
              )}

              {/* Notification Channels */}
              <div className="space-y-3">
                <label className="text-sm font-medium">Notification Channels</label>
                <div className="flex space-x-4">
                  <Checkbox
                    label="Email"
                    checked={formData.notification_channels?.includes('email')}
                    onChange={() => handleChannelToggle('email')}
                  />
                  <Checkbox
                    label="Webhook"
                    checked={formData.notification_channels?.includes('webhook')}
                    onChange={() => handleChannelToggle('webhook')}
                  />
                </div>
              </div>

              {formData.notification_channels?.includes('email') && (
                <FormField label="Email Recipients" hint="Comma-separated email addresses">
                  <Input
                    type="text"
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    placeholder="admin@example.com, security@example.com"
                  />
                </FormField>
              )}

              {formData.notification_channels?.includes('webhook') && (
                <FormField label="Webhook URL">
                  <Input
                    type="url"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://hooks.slack.com/services/..."
                  />
                </FormField>
              )}

              <Checkbox
                label="Enable immediately"
                checked={formData.is_active}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
              />

              <div className="flex space-x-2">
                <button
                  type="submit"
                  disabled={creating || editableDomains.length === 0}
                  className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                >
                  {creating && <Loader2 className="h-4 w-4 animate-spin" />}
                  <span>{creating ? 'Creating...' : 'Create Alert'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowCreateForm(false)}
                  className="rounded-md border px-4 py-2 text-sm font-medium hover:bg-gray-50"
                >
                  Cancel
                </button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Configured Alerts</CardTitle>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <div className="text-center py-8">
              <Bell className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground mb-4">
                {canManageAlerts
                  ? 'No alert rules configured. Create one to get notified about security events.'
                  : 'No alert rules configured.'}
              </p>
              {canManageAlerts && (
                <button
                  onClick={() => setShowCreateForm(true)}
                  className="inline-flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                >
                  <Plus className="h-4 w-4" />
                  <span>New Alert</span>
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {alerts.map((alert) => (
                <div
                  key={alert.id}
                  className="flex items-center justify-between rounded-lg border p-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <Bell className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium">{alert.name}</span>
                      <Badge variant={alert.is_active ? 'success' : 'secondary'}>
                        {alert.is_active ? 'Active' : 'Paused'}
                      </Badge>
                    </div>
                    {alert.description && (
                      <p className="text-sm text-muted-foreground">{alert.description}</p>
                    )}
                    <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                      <span>{alert.domain_name}</span>
                      <span>{getConditionDescription(alert.condition_type)}</span>
                    </div>
                    <div className="flex items-center space-x-2 text-xs text-muted-foreground">
                      {alert.notification_channels.includes('email') && (
                        <span className="flex items-center">
                          <Mail className="mr-1 h-3 w-3" />
                          Email
                        </span>
                      )}
                      {alert.notification_channels.includes('webhook') && (
                        <span className="flex items-center">
                          <Globe className="mr-1 h-3 w-3" />
                          Webhook
                        </span>
                      )}
                      <span>Created: {formatDate(alert.created_at)}</span>
                    </div>
                  </div>
                  {canEdit(alert.domain_name || '') && (
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleToggle(alert)}
                        disabled={togglingId === alert.id}
                        className="rounded-md p-2 hover:bg-gray-100 disabled:opacity-50"
                        title={alert.is_active ? 'Pause' : 'Resume'}
                      >
                        {togglingId === alert.id ? (
                          <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                        ) : alert.is_active ? (
                          <Pause className="h-4 w-4 text-orange-600" />
                        ) : (
                          <Play className="h-4 w-4 text-green-600" />
                        )}
                      </button>
                      <button
                        onClick={() => handleDelete(alert.id)}
                        disabled={deletingId === alert.id}
                        className="rounded-md p-2 hover:bg-gray-100 disabled:opacity-50"
                        title="Delete"
                      >
                        {deletingId === alert.id ? (
                          <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                        ) : (
                          <Trash2 className="h-4 w-4 text-red-600" />
                        )}
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>How Alerts Work</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Alert rules define conditions that trigger notifications when security events occur.
            Alerts are evaluated after each scan completes.
          </p>
          <p>
            <strong>Condition Types:</strong>
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li><strong>High Risk Files:</strong> Notifies when files exceed a risk score threshold</li>
            <li><strong>Public Files:</strong> Notifies when public files are detected</li>
            <li><strong>External Share:</strong> Notifies when files are shared externally</li>
            <li><strong>Inactive Users:</strong> Notifies about users inactive for specified days</li>
            <li><strong>No 2FA Users:</strong> Notifies about users without two-factor authentication</li>
            <li><strong>Risky OAuth Apps:</strong> Notifies about OAuth apps exceeding risk threshold</li>
            <li><strong>Security Findings:</strong> Notifies about security posture findings by severity</li>
            <li><strong>Scan Completed/Failed:</strong> Notifies when scans complete or fail</li>
          </ul>
          <p className="mt-3">
            <strong>Notification Channels:</strong> Email and webhook notifications are supported.
            For webhooks, a JSON payload with alert details is sent to the configured URL.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
