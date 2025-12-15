'use client'

import { useEffect, useState } from 'react'
import { api } from '@/lib/api'
import { ScheduledScan, ScheduledScanCreate, Domain } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SchedulesPageSkeleton } from '@/components/ui/skeleton'
import { useToast } from '@/components/ui/toast'
import { FormField, Input, Select, Checkbox } from '@/components/ui/form-input'
import { scheduleName, required, FormErrors } from '@/lib/validation'
import { formatDate } from '@/lib/utils'
import { Calendar, Clock, Play, Pause, Trash2, Plus, Loader2 } from 'lucide-react'
import { usePermissions } from '@/contexts/PermissionsContext'

export default function SchedulesPage() {
  const [loading, setLoading] = useState(true)
  const [schedules, setSchedules] = useState<ScheduledScan[]>([])
  const [domains, setDomains] = useState<Domain[]>([])
  const [error, setError] = useState<string | null>(null)
  const [showCreateForm, setShowCreateForm] = useState(false)
  const [creating, setCreating] = useState(false)
  const [togglingId, setTogglingId] = useState<number | null>(null)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const [formErrors, setFormErrors] = useState<FormErrors>({})
  const { success, error: showError } = useToast()
  const { canEdit, permissions } = usePermissions()

  // Check if user can manage schedules on any domain
  const canManageSchedules = permissions?.is_superuser || (permissions?.editable_domains.length ?? 0) > 0

  // Filter domains to only show ones user can edit (required for schedule management)
  const editableDomains = domains.filter(d => canEdit(d.name))

  // Form state
  const [formData, setFormData] = useState<ScheduledScanCreate>({
    name: '',
    domain_name: '',
    scan_type: 'all',
    schedule_type: 'daily',
    is_active: true,
  })

  const fetchData = async () => {
    try {
      const [schedulesData, domainsData] = await Promise.all([
        api.getScheduledScans(),
        api.getDomains(),
      ])
      setSchedules(schedulesData)
      setDomains(domainsData)
      if (domainsData.length > 0 && !formData.domain_name) {
        setFormData(prev => ({ ...prev, domain_name: domainsData[0].name }))
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load schedules')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleToggle = async (id: number, currentlyActive: boolean) => {
    setTogglingId(id)
    try {
      await api.toggleScheduledScan(id)
      await fetchData()
      success(
        currentlyActive ? 'Schedule paused' : 'Schedule activated',
        currentlyActive ? 'The scheduled scan has been paused.' : 'The scheduled scan is now active.'
      )
    } catch (err: any) {
      showError('Failed to update schedule', err.response?.data?.detail || 'Please try again.')
    } finally {
      setTogglingId(null)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this scheduled scan?')) return
    setDeletingId(id)
    try {
      await api.deleteScheduledScan(id)
      await fetchData()
      success('Schedule deleted', 'The scheduled scan has been removed.')
    } catch (err: any) {
      showError('Failed to delete schedule', err.response?.data?.detail || 'Please try again.')
    } finally {
      setDeletingId(null)
    }
  }

  const validateForm = (): boolean => {
    const errors: FormErrors = {}

    // Validate schedule name
    const nameResult = scheduleName(formData.name)
    if (!nameResult.valid) {
      errors.name = nameResult.error
    }

    // Validate domain selection
    const domainResult = required(formData.domain_name, 'Domain')
    if (!domainResult.valid) {
      errors.domain_name = domainResult.error
    }

    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!validateForm()) {
      return
    }

    setCreating(true)
    try {
      await api.createScheduledScan(formData)
      setShowCreateForm(false)
      setFormData({
        name: '',
        domain_name: domains[0]?.name || '',
        scan_type: 'all',
        schedule_type: 'daily',
        is_active: true,
      })
      setFormErrors({})
      await fetchData()
      success('Schedule created', `"${formData.name}" has been scheduled successfully.`)
    } catch (err: any) {
      showError('Failed to create schedule', err.response?.data?.detail || 'Please try again.')
    } finally {
      setCreating(false)
    }
  }

  const getScheduleDescription = (schedule: ScheduledScan) => {
    const config = schedule.schedule_config || {}
    switch (schedule.schedule_type) {
      case 'hourly':
        return 'Every hour'
      case 'daily':
        return `Daily at ${config.hour || 2}:00 UTC`
      case 'weekly':
        const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        return `Weekly on ${days[config.day_of_week || 0]} at ${config.hour || 2}:00 UTC`
      case 'monthly':
        return `Monthly on day ${config.day || 1} at ${config.hour || 2}:00 UTC`
      default:
        return schedule.schedule_type
    }
  }

  if (loading) {
    return <SchedulesPageSkeleton />
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Scheduled Scans</h1>
          <p className="text-muted-foreground">
            Configure automated security scans
          </p>
        </div>
        {canManageSchedules && (
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-4 w-4" />
            <span>New Schedule</span>
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
            <CardTitle>Create Scheduled Scan</CardTitle>
            <CardDescription>Set up a new automated scan schedule</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleCreate} className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <FormField label="Name" error={formErrors.name} required>
                  <Input
                    type="text"
                    value={formData.name}
                    onChange={(e) => {
                      setFormData({ ...formData, name: e.target.value })
                      if (formErrors.name) {
                        setFormErrors({ ...formErrors, name: undefined })
                      }
                    }}
                    error={!!formErrors.name}
                    placeholder="Daily Security Scan"
                  />
                </FormField>
                <FormField label="Domain" error={formErrors.domain_name} required>
                  <Select
                    value={formData.domain_name}
                    onChange={(e) => {
                      setFormData({ ...formData, domain_name: e.target.value })
                      if (formErrors.domain_name) {
                        setFormErrors({ ...formErrors, domain_name: undefined })
                      }
                    }}
                    error={!!formErrors.domain_name}
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
                    value={formData.scan_type}
                    onChange={(e) => setFormData({ ...formData, scan_type: e.target.value })}
                  >
                    <option value="all">All Scans</option>
                    <option value="posture">Security Posture</option>
                    <option value="files">Files</option>
                    <option value="users">Users</option>
                    <option value="oauth">OAuth Apps</option>
                  </Select>
                </FormField>
                <FormField label="Schedule">
                  <Select
                    value={formData.schedule_type}
                    onChange={(e) => setFormData({ ...formData, schedule_type: e.target.value })}
                  >
                    <option value="hourly">Hourly</option>
                    <option value="daily">Daily (2:00 AM UTC)</option>
                    <option value="weekly">Weekly (Monday 2:00 AM UTC)</option>
                    <option value="monthly">Monthly (1st at 2:00 AM UTC)</option>
                  </Select>
                </FormField>
              </div>
              <Checkbox
                label="Enable immediately"
                checked={formData.is_active}
                onChange={(e) => setFormData({ ...formData, is_active: e.target.checked })}
              />
              <div className="flex space-x-2">
                <button
                  type="submit"
                  disabled={creating}
                  className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                >
                  {creating && <Loader2 className="h-4 w-4 animate-spin" />}
                  <span>{creating ? 'Creating...' : 'Create Schedule'}</span>
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
          <CardTitle>Configured Schedules</CardTitle>
        </CardHeader>
        <CardContent>
          {schedules.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-muted-foreground mb-4">
                {canManageSchedules
                  ? 'No scheduled scans configured. Create one to automate your security scans.'
                  : 'No scheduled scans configured.'}
              </p>
              {canManageSchedules && (
                <button
                  onClick={() => setShowCreateForm(true)}
                  className="inline-flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                >
                  <Plus className="h-4 w-4" />
                  <span>New Schedule</span>
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {schedules.map((schedule) => (
                <div
                  key={schedule.id}
                  className="flex items-center justify-between rounded-lg border p-4"
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span className="font-medium">{schedule.name}</span>
                      <Badge variant={schedule.is_active ? 'success' : 'secondary'}>
                        {schedule.is_active ? 'Active' : 'Paused'}
                      </Badge>
                    </div>
                    <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                      <span>{schedule.domain_name}</span>
                      <span className="capitalize">{schedule.scan_type} scan</span>
                    </div>
                    <div className="flex items-center space-x-4 text-sm text-muted-foreground">
                      <span className="flex items-center">
                        <Clock className="mr-1 h-3 w-3" />
                        {getScheduleDescription(schedule)}
                      </span>
                      {schedule.next_run && (
                        <span className="flex items-center">
                          <Calendar className="mr-1 h-3 w-3" />
                          Next: {formatDate(schedule.next_run)}
                        </span>
                      )}
                    </div>
                    {schedule.last_run && (
                      <p className="text-xs text-muted-foreground">
                        Last run: {formatDate(schedule.last_run)}
                      </p>
                    )}
                  </div>
                  {canEdit(schedule.domain_name) && (
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleToggle(schedule.id, schedule.is_active)}
                        disabled={togglingId === schedule.id}
                        className="rounded-md p-2 hover:bg-gray-100 disabled:opacity-50"
                        title={schedule.is_active ? 'Pause' : 'Resume'}
                      >
                        {togglingId === schedule.id ? (
                          <Loader2 className="h-4 w-4 animate-spin text-gray-500" />
                        ) : schedule.is_active ? (
                          <Pause className="h-4 w-4 text-orange-600" />
                        ) : (
                          <Play className="h-4 w-4 text-green-600" />
                        )}
                      </button>
                      <button
                        onClick={() => handleDelete(schedule.id)}
                        disabled={deletingId === schedule.id}
                        className="rounded-md p-2 hover:bg-gray-100 disabled:opacity-50"
                        title="Delete"
                      >
                        {deletingId === schedule.id ? (
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
          <CardTitle>How Scheduled Scans Work</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Scheduled scans require a background worker process to be running. The web UI only configures
            the schedules - actual scan execution happens via the CLI.
          </p>
          <p>
            To run scheduled scans, you need to set up a cron job or systemd timer that checks for due
            schedules and executes the Vaulytica CLI with the appropriate parameters.
          </p>
          <p className="font-mono text-xs bg-gray-100 p-2 rounded">
            # Example cron entry (runs every hour to check for due scans)<br />
            0 * * * * vaulytica schedule run --db-url postgresql://...
          </p>
        </CardContent>
      </Card>
    </div>
  )
}
