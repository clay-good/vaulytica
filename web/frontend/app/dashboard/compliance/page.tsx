'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { api } from '@/lib/api'
import { ComplianceReportSummary, FrameworkInfo, Domain, ScheduledReport } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/toast'
import { FormField, Select, Input } from '@/components/ui/form-input'
import { formatDate } from '@/lib/utils'
import { FileText, Plus, Loader2, Trash2, Shield, CheckCircle, XCircle, AlertTriangle, Calendar, Clock, Pause, Play, Mail } from 'lucide-react'
import { usePermissions } from '@/contexts/PermissionsContext'

const frameworkColors: Record<string, string> = {
  gdpr: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  hipaa: 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200',
  soc2: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  'pci-dss': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  ferpa: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
  fedramp: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
}

export default function CompliancePage() {
  const [loading, setLoading] = useState(true)
  const [reports, setReports] = useState<ComplianceReportSummary[]>([])
  const [frameworks, setFrameworks] = useState<FrameworkInfo[]>([])
  const [domains, setDomains] = useState<Domain[]>([])
  const [error, setError] = useState<string | null>(null)
  const [showGenerateForm, setShowGenerateForm] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [deletingId, setDeletingId] = useState<number | null>(null)
  const { success, error: showError } = useToast()
  const { canEdit, permissions } = usePermissions()

  // Tab state
  const [activeTab, setActiveTab] = useState<'reports' | 'schedules'>('reports')

  // Scheduled reports state
  const [scheduledReports, setScheduledReports] = useState<ScheduledReport[]>([])
  const [showScheduleForm, setShowScheduleForm] = useState(false)
  const [savingSchedule, setSavingSchedule] = useState(false)
  const [togglingScheduleId, setTogglingScheduleId] = useState<number | null>(null)
  const [deletingScheduleId, setDeletingScheduleId] = useState<number | null>(null)

  // Schedule form state
  const [scheduleName, setScheduleName] = useState('')
  const [scheduleDomainn, setScheduleDomain] = useState('')
  const [scheduleFramework, setScheduleFramework] = useState('gdpr')
  const [scheduleType, setScheduleType] = useState('weekly')
  const [scheduleHour, setScheduleHour] = useState(6)
  const [scheduleDayOfWeek, setScheduleDayOfWeek] = useState(1) // Monday
  const [scheduleDayOfMonth, setScheduleDayOfMonth] = useState(1)
  const [scheduleRecipients, setScheduleRecipients] = useState('')

  // Form state
  const [selectedDomain, setSelectedDomain] = useState('')
  const [selectedFramework, setSelectedFramework] = useState('gdpr')

  // Filter state
  const [filterDomain, setFilterDomain] = useState('')
  const [filterFramework, setFilterFramework] = useState('')

  // Check if user can generate reports on any domain
  const canGenerateReports = permissions?.is_superuser || (permissions?.editable_domains.length ?? 0) > 0

  // Filter domains to only show ones user can edit
  const editableDomains = domains.filter(d => canEdit(d.name))

  const fetchData = async () => {
    try {
      const [reportsData, frameworksData, domainsData, schedulesData] = await Promise.all([
        api.getComplianceReports(filterDomain || undefined, filterFramework || undefined).then(r => r.items),
        api.getComplianceFrameworks(),
        api.getDomains(),
        api.getScheduledReports().then(r => r.items),
      ])
      setReports(reportsData)
      setFrameworks(frameworksData)
      setDomains(domainsData)
      setScheduledReports(schedulesData)
      if (domainsData.length > 0 && !selectedDomain) {
        const firstEditable = domainsData.find(d => canEdit(d.name))
        if (firstEditable) {
          setSelectedDomain(firstEditable.name)
          setScheduleDomain(firstEditable.name)
        }
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load compliance data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [filterDomain, filterFramework])

  const handleGenerate = async () => {
    if (!selectedDomain) {
      showError('No domain selected', 'Please select a domain.')
      return
    }

    setGenerating(true)
    try {
      const report = await api.generateComplianceReport({
        domain_name: selectedDomain,
        framework: selectedFramework,
      })
      setShowGenerateForm(false)
      success('Report generated', `${selectedFramework.toUpperCase()} compliance report generated with ${report.compliance_score}% score.`)
      await fetchData()
    } catch (err: any) {
      showError('Failed to generate report', err.response?.data?.detail || 'Please try again.')
    } finally {
      setGenerating(false)
    }
  }

  const handleDelete = async (id: number) => {
    if (!confirm('Are you sure you want to delete this compliance report?')) return
    setDeletingId(id)
    try {
      await api.deleteComplianceReport(id)
      success('Report deleted', 'The compliance report has been removed.')
      await fetchData()
    } catch (err: any) {
      showError('Failed to delete report', err.response?.data?.detail || 'Please try again.')
    } finally {
      setDeletingId(null)
    }
  }

  const handleCreateSchedule = async () => {
    if (!scheduleName.trim()) {
      showError('Name required', 'Please enter a name for the scheduled report.')
      return
    }
    if (!scheduleDomainn) {
      showError('Domain required', 'Please select a domain.')
      return
    }

    setSavingSchedule(true)
    try {
      const scheduleConfig: Record<string, any> = { hour: scheduleHour }
      if (scheduleType === 'weekly') {
        scheduleConfig.day_of_week = scheduleDayOfWeek
      } else if (scheduleType === 'monthly') {
        scheduleConfig.day = scheduleDayOfMonth
      }

      const recipients = scheduleRecipients.split(',').map(e => e.trim()).filter(e => e.length > 0)

      await api.createScheduledReport({
        name: scheduleName,
        domain_name: scheduleDomainn,
        framework: scheduleFramework,
        schedule_type: scheduleType,
        schedule_config: scheduleConfig,
        recipients: recipients.length > 0 ? recipients : undefined,
      })

      setShowScheduleForm(false)
      setScheduleName('')
      setScheduleRecipients('')
      success('Schedule created', 'The report schedule has been created.')
      await fetchData()
    } catch (err: any) {
      showError('Failed to create schedule', err.response?.data?.detail || 'Please try again.')
    } finally {
      setSavingSchedule(false)
    }
  }

  const handleToggleSchedule = async (id: number) => {
    setTogglingScheduleId(id)
    try {
      await api.toggleScheduledReport(id)
      success('Schedule updated', 'The schedule status has been toggled.')
      await fetchData()
    } catch (err: any) {
      showError('Failed to toggle schedule', err.response?.data?.detail || 'Please try again.')
    } finally {
      setTogglingScheduleId(null)
    }
  }

  const handleDeleteSchedule = async (id: number) => {
    if (!confirm('Are you sure you want to delete this scheduled report?')) return
    setDeletingScheduleId(id)
    try {
      await api.deleteScheduledReport(id)
      success('Schedule deleted', 'The scheduled report has been removed.')
      await fetchData()
    } catch (err: any) {
      showError('Failed to delete schedule', err.response?.data?.detail || 'Please try again.')
    } finally {
      setDeletingScheduleId(null)
    }
  }

  const getScoreColor = (score: number | null) => {
    if (score === null) return 'text-gray-500 dark:text-gray-400'
    if (score >= 80) return 'text-green-600 dark:text-green-400'
    if (score >= 60) return 'text-yellow-600 dark:text-yellow-400'
    return 'text-red-600 dark:text-red-400'
  }

  const getScoreBgColor = (score: number | null) => {
    if (score === null) return 'bg-gray-100 dark:bg-gray-700'
    if (score >= 80) return 'bg-green-100 dark:bg-green-900'
    if (score >= 60) return 'bg-yellow-100 dark:bg-yellow-900'
    return 'bg-red-100 dark:bg-red-900'
  }

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="h-8 w-48 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
            <div className="h-4 w-64 bg-gray-100 dark:bg-gray-800 rounded animate-pulse mt-2" />
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          {[1, 2, 3].map(i => (
            <div key={i} className="h-32 bg-gray-100 dark:bg-gray-800 rounded animate-pulse" />
          ))}
        </div>
        <Card>
          <CardHeader>
            <div className="h-6 w-40 bg-gray-200 dark:bg-gray-700 rounded animate-pulse" />
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[1, 2, 3].map(i => (
                <div key={i} className="h-24 bg-gray-100 dark:bg-gray-800 rounded animate-pulse" />
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
          <h1 className="text-3xl font-bold">Compliance Reports</h1>
          <p className="text-muted-foreground">
            Generate and view compliance assessment reports
          </p>
        </div>
        {canGenerateReports && (
          <button
            onClick={() => setShowGenerateForm(!showGenerateForm)}
            className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          >
            <Plus className="h-4 w-4" />
            <span>Generate Report</span>
          </button>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/30 p-4">
          <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
          <button
            onClick={() => setError(null)}
            className="mt-2 text-sm text-red-600 dark:text-red-400 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('reports')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'reports'
                ? 'border-primary text-primary'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-300 dark:hover:border-gray-600'
            }`}
          >
            <FileText className="h-4 w-4 inline mr-2" />
            Reports
          </button>
          <button
            onClick={() => setActiveTab('schedules')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'schedules'
                ? 'border-primary text-primary'
                : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 hover:border-gray-300 dark:hover:border-gray-600'
            }`}
          >
            <Calendar className="h-4 w-4 inline mr-2" />
            Scheduled Reports ({scheduledReports.length})
          </button>
        </nav>
      </div>

      {/* Schedules Tab */}
      {activeTab === 'schedules' && (
        <div className="space-y-6">
          {/* Create Schedule Button */}
          {canGenerateReports && (
            <div className="flex justify-end">
              <button
                onClick={() => setShowScheduleForm(!showScheduleForm)}
                className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
              >
                <Plus className="h-4 w-4" />
                <span>New Schedule</span>
              </button>
            </div>
          )}

          {/* Create Schedule Form */}
          {showScheduleForm && (
            <Card>
              <CardHeader>
                <CardTitle>Create Report Schedule</CardTitle>
                <CardDescription>Set up automatic compliance report generation</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-2">
                  <FormField label="Schedule Name" required>
                    <Input
                      value={scheduleName}
                      onChange={(e) => setScheduleName(e.target.value)}
                      placeholder="e.g., Weekly GDPR Report"
                    />
                  </FormField>
                  <FormField label="Domain" required>
                    <Select
                      value={scheduleDomainn}
                      onChange={(e) => setScheduleDomain(e.target.value)}
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
                  <FormField label="Framework" required>
                    <Select
                      value={scheduleFramework}
                      onChange={(e) => setScheduleFramework(e.target.value)}
                    >
                      {frameworks.map((fw) => (
                        <option key={fw.id} value={fw.id}>
                          {fw.name}
                        </option>
                      ))}
                    </Select>
                  </FormField>
                  <FormField label="Schedule Type" required>
                    <Select
                      value={scheduleType}
                      onChange={(e) => setScheduleType(e.target.value)}
                    >
                      <option value="daily">Daily</option>
                      <option value="weekly">Weekly</option>
                      <option value="monthly">Monthly</option>
                    </Select>
                  </FormField>
                  <FormField label="Hour (UTC)" required>
                    <Select
                      value={scheduleHour}
                      onChange={(e) => setScheduleHour(Number(e.target.value))}
                    >
                      {Array.from({ length: 24 }, (_, i) => (
                        <option key={i} value={i}>
                          {i.toString().padStart(2, '0')}:00
                        </option>
                      ))}
                    </Select>
                  </FormField>
                  {scheduleType === 'weekly' && (
                    <FormField label="Day of Week">
                      <Select
                        value={scheduleDayOfWeek}
                        onChange={(e) => setScheduleDayOfWeek(Number(e.target.value))}
                      >
                        <option value={0}>Monday</option>
                        <option value={1}>Tuesday</option>
                        <option value={2}>Wednesday</option>
                        <option value={3}>Thursday</option>
                        <option value={4}>Friday</option>
                        <option value={5}>Saturday</option>
                        <option value={6}>Sunday</option>
                      </Select>
                    </FormField>
                  )}
                  {scheduleType === 'monthly' && (
                    <FormField label="Day of Month">
                      <Select
                        value={scheduleDayOfMonth}
                        onChange={(e) => setScheduleDayOfMonth(Number(e.target.value))}
                      >
                        {Array.from({ length: 28 }, (_, i) => (
                          <option key={i + 1} value={i + 1}>
                            {i + 1}
                          </option>
                        ))}
                      </Select>
                    </FormField>
                  )}
                  <FormField label="Email Recipients (comma-separated)">
                    <Input
                      value={scheduleRecipients}
                      onChange={(e) => setScheduleRecipients(e.target.value)}
                      placeholder="email1@example.com, email2@example.com"
                    />
                  </FormField>
                </div>
                <div className="mt-4 flex space-x-2">
                  <button
                    onClick={handleCreateSchedule}
                    disabled={savingSchedule || editableDomains.length === 0}
                    className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
                  >
                    {savingSchedule && <Loader2 className="h-4 w-4 animate-spin" />}
                    <span>{savingSchedule ? 'Creating...' : 'Create Schedule'}</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowScheduleForm(false)}
                    className="rounded-md border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-700"
                  >
                    Cancel
                  </button>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Scheduled Reports List */}
          <Card>
            <CardHeader>
              <CardTitle>Report Schedules</CardTitle>
            </CardHeader>
            <CardContent>
              {scheduledReports.length === 0 ? (
                <div className="text-center py-8">
                  <Calendar className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <p className="text-muted-foreground mb-4">
                    {canGenerateReports
                      ? 'No scheduled reports. Create one to automatically generate compliance reports.'
                      : 'No scheduled reports found.'}
                  </p>
                  {canGenerateReports && (
                    <button
                      onClick={() => setShowScheduleForm(true)}
                      className="inline-flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                    >
                      <Plus className="h-4 w-4" />
                      <span>New Schedule</span>
                    </button>
                  )}
                </div>
              ) : (
                <div className="space-y-4">
                  {scheduledReports.map((schedule) => (
                    <div
                      key={schedule.id}
                      className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-700 p-4 hover:bg-gray-50 dark:hover:bg-gray-700"
                    >
                      <div className="flex items-center space-x-4">
                        <div className={`p-2 rounded-lg ${schedule.is_active ? 'bg-green-100 dark:bg-green-900' : 'bg-gray-100 dark:bg-gray-700'}`}>
                          {schedule.is_active ? (
                            <Play className="h-5 w-5 text-green-600 dark:text-green-400" />
                          ) : (
                            <Pause className="h-5 w-5 text-gray-500 dark:text-gray-400" />
                          )}
                        </div>
                        <div>
                          <div className="flex items-center space-x-2">
                            <span className="font-medium">{schedule.name}</span>
                            <span className={`text-xs font-medium px-2 py-1 rounded ${frameworkColors[schedule.framework] || 'bg-gray-100 text-gray-800'}`}>
                              {schedule.framework.toUpperCase()}
                            </span>
                            <Badge variant={schedule.is_active ? 'success' : 'secondary'}>
                              {schedule.is_active ? 'Active' : 'Paused'}
                            </Badge>
                          </div>
                          <div className="flex items-center space-x-4 mt-1 text-sm text-muted-foreground">
                            <span>{schedule.domain_name}</span>
                            <span className="flex items-center">
                              <Clock className="h-3 w-3 mr-1" />
                              {schedule.schedule_type}
                              {schedule.schedule_config?.hour !== undefined && ` at ${schedule.schedule_config.hour.toString().padStart(2, '0')}:00 UTC`}
                            </span>
                            {schedule.next_run && (
                              <span>Next: {formatDate(schedule.next_run)}</span>
                            )}
                            {schedule.recipients && schedule.recipients.length > 0 && (
                              <span className="flex items-center">
                                <Mail className="h-3 w-3 mr-1" />
                                {schedule.recipients.length} recipient{schedule.recipients.length > 1 ? 's' : ''}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        {canEdit(schedule.domain_name) && (
                          <>
                            <button
                              onClick={() => handleToggleSchedule(schedule.id)}
                              disabled={togglingScheduleId === schedule.id}
                              className="rounded-md p-2 hover:bg-gray-100 dark:hover:bg-gray-600 disabled:opacity-50"
                              title={schedule.is_active ? 'Pause' : 'Resume'}
                            >
                              {togglingScheduleId === schedule.id ? (
                                <Loader2 className="h-4 w-4 animate-spin text-gray-500 dark:text-gray-400" />
                              ) : schedule.is_active ? (
                                <Pause className="h-4 w-4 text-orange-600 dark:text-orange-400" />
                              ) : (
                                <Play className="h-4 w-4 text-green-600 dark:text-green-400" />
                              )}
                            </button>
                            <button
                              onClick={() => handleDeleteSchedule(schedule.id)}
                              disabled={deletingScheduleId === schedule.id}
                              className="rounded-md p-2 hover:bg-gray-100 dark:hover:bg-gray-600 disabled:opacity-50"
                              title="Delete"
                            >
                              {deletingScheduleId === schedule.id ? (
                                <Loader2 className="h-4 w-4 animate-spin text-gray-500 dark:text-gray-400" />
                              ) : (
                                <Trash2 className="h-4 w-4 text-red-600 dark:text-red-400" />
                              )}
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}

      {/* Reports Tab */}
      {activeTab === 'reports' && (
        <>
      {/* Framework Overview Cards */}
      <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6">
        {frameworks.map((fw) => (
          <Card key={fw.id} className="cursor-pointer hover:shadow-md transition-shadow" onClick={() => setFilterFramework(filterFramework === fw.id ? '' : fw.id)}>
            <CardContent className="pt-4">
              <div className="flex items-center justify-between mb-2">
                <span className={`text-xs font-medium px-2 py-1 rounded ${frameworkColors[fw.id] || 'bg-gray-100 text-gray-800'}`}>
                  {fw.name}
                </span>
                {filterFramework === fw.id && (
                  <CheckCircle className="h-4 w-4 text-primary" />
                )}
              </div>
              <p className="text-xs text-muted-foreground line-clamp-2">
                {fw.description}
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                {fw.check_count} checks
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Generate Report Form */}
      {showGenerateForm && (
        <Card>
          <CardHeader>
            <CardTitle>Generate Compliance Report</CardTitle>
            <CardDescription>Run a compliance assessment against a specific framework</CardDescription>
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
              <FormField label="Framework" required>
                <Select
                  value={selectedFramework}
                  onChange={(e) => setSelectedFramework(e.target.value)}
                >
                  {frameworks.map((fw) => (
                    <option key={fw.id} value={fw.id}>
                      {fw.name} - {fw.description.substring(0, 40)}...
                    </option>
                  ))}
                </Select>
              </FormField>
            </div>
            <div className="mt-4 flex space-x-2">
              <button
                onClick={handleGenerate}
                disabled={generating || editableDomains.length === 0}
                className="flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {generating && <Loader2 className="h-4 w-4 animate-spin" />}
                <span>{generating ? 'Generating...' : 'Generate Report'}</span>
              </button>
              <button
                type="button"
                onClick={() => setShowGenerateForm(false)}
                className="rounded-md border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <Card>
        <CardContent className="pt-4">
          <div className="grid gap-4 md:grid-cols-3">
            <FormField label="Filter by Domain">
              <Select
                value={filterDomain}
                onChange={(e) => setFilterDomain(e.target.value)}
              >
                <option value="">All Domains</option>
                {domains.map((domain) => (
                  <option key={domain.id} value={domain.name}>
                    {domain.display_name || domain.name}
                  </option>
                ))}
              </Select>
            </FormField>
            <FormField label="Filter by Framework">
              <Select
                value={filterFramework}
                onChange={(e) => setFilterFramework(e.target.value)}
              >
                <option value="">All Frameworks</option>
                {frameworks.map((fw) => (
                  <option key={fw.id} value={fw.id}>
                    {fw.name}
                  </option>
                ))}
              </Select>
            </FormField>
            <div className="flex items-end">
              <button
                onClick={() => { setFilterDomain(''); setFilterFramework(''); }}
                className="rounded-md border border-gray-300 dark:border-gray-600 px-4 py-2 text-sm font-medium hover:bg-gray-50 dark:hover:bg-gray-700"
              >
                Clear Filters
              </button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Reports List */}
      <Card>
        <CardHeader>
          <CardTitle>Generated Reports</CardTitle>
        </CardHeader>
        <CardContent>
          {reports.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-muted-foreground mb-4">
                {canGenerateReports
                  ? 'No compliance reports found. Generate one to assess your security posture.'
                  : 'No compliance reports found.'}
              </p>
              {canGenerateReports && (
                <button
                  onClick={() => setShowGenerateForm(true)}
                  className="inline-flex items-center space-x-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                >
                  <Plus className="h-4 w-4" />
                  <span>Generate Report</span>
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {reports.map((report) => (
                <div
                  key={report.id}
                  className="flex items-center justify-between rounded-lg border border-gray-200 dark:border-gray-700 p-4 hover:bg-gray-50 dark:hover:bg-gray-700"
                >
                  <div className="flex items-center space-x-4">
                    <div className={`p-3 rounded-lg ${getScoreBgColor(report.compliance_score)}`}>
                      <span className={`text-2xl font-bold ${getScoreColor(report.compliance_score)}`}>
                        {report.compliance_score !== null ? `${report.compliance_score}%` : 'N/A'}
                      </span>
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className={`text-xs font-medium px-2 py-1 rounded ${frameworkColors[report.framework] || 'bg-gray-100 text-gray-800'}`}>
                          {report.framework.toUpperCase()}
                        </span>
                        <span className="font-medium">{report.domain_name}</span>
                        <Badge variant={report.status === 'completed' ? 'success' : report.status === 'failed' ? 'danger' : 'secondary'}>
                          {report.status}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-4 mt-1 text-sm text-muted-foreground">
                        <span className="flex items-center">
                          <CheckCircle className="h-3 w-3 mr-1 text-green-600" />
                          {report.passed_checks} passed
                        </span>
                        <span className="flex items-center">
                          <XCircle className="h-3 w-3 mr-1 text-red-600" />
                          {report.failed_checks} failed
                        </span>
                        <span>Generated: {formatDate(report.generated_at)}</span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Link
                      href={`/dashboard/compliance/${report.id}`}
                      className="rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90"
                    >
                      View Details
                    </Link>
                    {canEdit(report.domain_name) && (
                      <button
                        onClick={() => handleDelete(report.id)}
                        disabled={deletingId === report.id}
                        className="rounded-md p-2 hover:bg-gray-100 dark:hover:bg-gray-600 disabled:opacity-50"
                        title="Delete"
                      >
                        {deletingId === report.id ? (
                          <Loader2 className="h-4 w-4 animate-spin text-gray-500 dark:text-gray-400" />
                        ) : (
                          <Trash2 className="h-4 w-4 text-red-600 dark:text-red-400" />
                        )}
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Info Card */}
      <Card>
        <CardHeader>
          <CardTitle>About Compliance Reports</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            Compliance reports assess your Google Workspace security posture against industry-standard frameworks.
            Reports are generated based on the latest scan data available for your domain.
          </p>
          <p>
            <strong>Supported Frameworks:</strong>
          </p>
          <ul className="list-disc list-inside space-y-1 ml-2">
            <li><strong>GDPR:</strong> General Data Protection Regulation - EU data privacy</li>
            <li><strong>HIPAA:</strong> Health Insurance Portability and Accountability Act - Healthcare data</li>
            <li><strong>SOC 2:</strong> Service Organization Control 2 - Trust services criteria</li>
            <li><strong>PCI-DSS:</strong> Payment Card Industry Data Security Standard</li>
            <li><strong>FERPA:</strong> Family Educational Rights and Privacy Act - Student data</li>
            <li><strong>FedRAMP:</strong> Federal Risk and Authorization Management Program</li>
          </ul>
          <p className="mt-3">
            <strong>Note:</strong> For accurate compliance assessments, ensure you have recent scan data by running
            security scans (files, users, oauth, security posture) before generating reports.
          </p>
        </CardContent>
      </Card>
        </>
      )}
    </div>
  )
}
