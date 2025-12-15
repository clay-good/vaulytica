'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { api } from '@/lib/api'
import { ComplianceReport, ComplianceIssue } from '@/lib/types'
import { usePermissions } from '@/contexts/PermissionsContext'
import { exportToPDF, formatPrintDate } from '@/lib/pdf-export'
import {
  ArrowLeft,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Download,
  Shield,
  FileText,
  Clock,
} from 'lucide-react'

export default function ComplianceReportDetailPage() {
  const params = useParams()
  const router = useRouter()
  const { permissions } = usePermissions()
  const [report, setReport] = useState<ComplianceReport | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [filterCategory, setFilterCategory] = useState<string>('all')

  useEffect(() => {
    loadReport()
  }, [params.id])

  const loadReport = async () => {
    try {
      setLoading(true)
      const data = await api.getComplianceReport(Number(params.id))
      setReport(data)
      setError(null)
    } catch (err: any) {
      setError(err.message || 'Failed to load compliance report')
    } finally {
      setLoading(false)
    }
  }

  const getScoreColor = (score: number | null) => {
    if (score === null) return 'text-gray-500'
    if (score >= 80) return 'text-green-600'
    if (score >= 60) return 'text-yellow-600'
    return 'text-red-600'
  }

  const getScoreBgColor = (score: number | null) => {
    if (score === null) return 'bg-gray-100'
    if (score >= 80) return 'bg-green-100'
    if (score >= 60) return 'bg-yellow-100'
    return 'bg-red-100'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-800'
      case 'high':
        return 'bg-orange-100 text-orange-800'
      case 'medium':
        return 'bg-yellow-100 text-yellow-800'
      case 'low':
        return 'bg-blue-100 text-blue-800'
      default:
        return 'bg-gray-100 text-gray-800'
    }
  }

  const getFrameworkDisplayName = (framework: string) => {
    const names: Record<string, string> = {
      'gdpr': 'GDPR',
      'hipaa': 'HIPAA',
      'soc2': 'SOC 2',
      'pci-dss': 'PCI-DSS',
      'ferpa': 'FERPA',
      'fedramp': 'FedRAMP',
    }
    return names[framework] || framework.toUpperCase()
  }

  const categories = report?.issues
    ? Array.from(new Set(report.issues.map(i => i.category)))
    : []

  const filteredIssues = report?.issues?.filter(issue => {
    if (filterSeverity !== 'all' && issue.severity.toLowerCase() !== filterSeverity) {
      return false
    }
    if (filterCategory !== 'all' && issue.category !== filterCategory) {
      return false
    }
    return true
  }) || []

  const handleExportPDF = () => {
    if (!report) return
    const frameworkName = getFrameworkDisplayName(report.framework)
    exportToPDF({
      title: `${frameworkName} Compliance Report - ${report.domain_name}`,
      orientation: 'portrait',
      paperSize: 'a4'
    })
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  if (error || !report) {
    return (
      <div className="space-y-6">
        <button
          onClick={() => router.back()}
          className="flex items-center text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back
        </button>
        <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
          {error || 'Report not found'}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 print:space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between print:hidden">
        <button
          onClick={() => router.back()}
          className="flex items-center text-gray-600 hover:text-gray-900"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to Reports
        </button>
        <button
          onClick={handleExportPDF}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Download className="h-4 w-4" />
          Export PDF
        </button>
      </div>

      {/* Report Header */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-blue-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-900">
                  {getFrameworkDisplayName(report.framework)} Compliance Report
                </h1>
                <p className="text-gray-500">{report.domain_name}</p>
              </div>
            </div>
            <div className="mt-4 flex items-center gap-4 text-sm text-gray-500">
              <span className="flex items-center gap-1">
                <Clock className="h-4 w-4" />
                Generated: {new Date(report.generated_at).toLocaleString()}
              </span>
              <span className={`px-2 py-1 rounded text-xs font-medium ${
                report.status === 'completed'
                  ? 'bg-green-100 text-green-800'
                  : report.status === 'failed'
                  ? 'bg-red-100 text-red-800'
                  : 'bg-yellow-100 text-yellow-800'
              }`}>
                {report.status.toUpperCase()}
              </span>
            </div>
          </div>
          <div className={`text-center px-6 py-4 rounded-lg ${getScoreBgColor(report.compliance_score)}`}>
            <div className={`text-4xl font-bold ${getScoreColor(report.compliance_score)}`}>
              {report.compliance_score !== null ? `${report.compliance_score}%` : 'N/A'}
            </div>
            <div className="text-sm text-gray-600">Compliance Score</div>
          </div>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-gray-500 text-sm mb-1">
            <FileText className="h-4 w-4" />
            Total Checks
          </div>
          <div className="text-2xl font-bold text-gray-900">{report.total_checks}</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-green-600 text-sm mb-1">
            <CheckCircle className="h-4 w-4" />
            Passed
          </div>
          <div className="text-2xl font-bold text-green-600">{report.passed_checks}</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-red-600 text-sm mb-1">
            <XCircle className="h-4 w-4" />
            Failed
          </div>
          <div className="text-2xl font-bold text-red-600">{report.failed_checks}</div>
        </div>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4">
          <div className="flex items-center gap-2 text-orange-600 text-sm mb-1">
            <AlertTriangle className="h-4 w-4" />
            Critical/High
          </div>
          <div className="text-2xl font-bold text-orange-600">
            {report.critical_count + report.high_count}
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Issues by Severity</h2>
        <div className="flex gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-red-600"></span>
            <span className="text-sm text-gray-600">Critical: {report.critical_count}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-orange-500"></span>
            <span className="text-sm text-gray-600">High: {report.high_count}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-yellow-500"></span>
            <span className="text-sm text-gray-600">Medium: {report.medium_count}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full bg-blue-500"></span>
            <span className="text-sm text-gray-600">Low: {report.low_count}</span>
          </div>
        </div>
        <div className="mt-4 h-4 bg-gray-100 rounded-full overflow-hidden flex">
          {report.critical_count > 0 && (
            <div
              className="bg-red-600 h-full"
              style={{ width: `${(report.critical_count / report.failed_checks) * 100}%` }}
            />
          )}
          {report.high_count > 0 && (
            <div
              className="bg-orange-500 h-full"
              style={{ width: `${(report.high_count / report.failed_checks) * 100}%` }}
            />
          )}
          {report.medium_count > 0 && (
            <div
              className="bg-yellow-500 h-full"
              style={{ width: `${(report.medium_count / report.failed_checks) * 100}%` }}
            />
          )}
          {report.low_count > 0 && (
            <div
              className="bg-blue-500 h-full"
              style={{ width: `${(report.low_count / report.failed_checks) * 100}%` }}
            />
          )}
        </div>
      </div>

      {/* Issues List */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <h2 className="text-lg font-semibold text-gray-900">
              Compliance Issues ({filteredIssues.length})
            </h2>
            <div className="flex gap-3 print:hidden">
              <select
                value={filterSeverity}
                onChange={(e) => setFilterSeverity(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={filterCategory}
                onChange={(e) => setFilterCategory(e.target.value)}
                className="px-3 py-2 border border-gray-300 rounded-lg text-sm"
              >
                <option value="all">All Categories</option>
                {categories.map(cat => (
                  <option key={cat} value={cat}>{cat}</option>
                ))}
              </select>
            </div>
          </div>
        </div>

        {filteredIssues.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            {report.issues?.length === 0
              ? 'No compliance issues found - all checks passed!'
              : 'No issues match the selected filters'
            }
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {filteredIssues.map((issue, index) => (
              <div key={index} className="p-6">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(issue.severity)}`}>
                        {issue.severity.toUpperCase()}
                      </span>
                      <span className="text-xs text-gray-500 bg-gray-100 px-2 py-1 rounded">
                        {issue.category}
                      </span>
                      <code className="text-xs text-gray-500 font-mono">
                        {issue.check_id}
                      </code>
                    </div>
                    <h3 className="text-base font-medium text-gray-900 mb-1">
                      {issue.title}
                    </h3>
                    {issue.description && (
                      <p className="text-sm text-gray-600 mb-3">
                        {issue.description}
                      </p>
                    )}
                    {issue.resource_type && issue.resource_id && (
                      <div className="text-xs text-gray-500 mb-2">
                        <span className="font-medium">Affected Resource:</span>{' '}
                        {issue.resource_type}: {issue.resource_id}
                      </div>
                    )}
                    {issue.remediation && (
                      <div className="mt-3 p-3 bg-blue-50 rounded-lg">
                        <div className="text-xs font-medium text-blue-800 mb-1">
                          Recommended Remediation:
                        </div>
                        <p className="text-sm text-blue-700">
                          {issue.remediation}
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Print Styles */}
      <style jsx global>{`
        @media print {
          body {
            print-color-adjust: exact;
            -webkit-print-color-adjust: exact;
          }
          .print\\:hidden {
            display: none !important;
          }
          .print\\:space-y-4 > * + * {
            margin-top: 1rem;
          }
        }
      `}</style>
    </div>
  )
}
