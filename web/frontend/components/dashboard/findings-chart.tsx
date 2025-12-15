'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'

interface FindingsChartProps {
  data: Record<string, number>
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#2563eb',
  unknown: '#6b7280',
}

export function FindingsChart({ data }: FindingsChartProps) {
  const chartData = Object.entries(data).map(([severity, count]) => ({
    severity: severity.charAt(0).toUpperCase() + severity.slice(1),
    count,
    fill: SEVERITY_COLORS[severity.toLowerCase()] || SEVERITY_COLORS.unknown,
  }))

  // Sort by severity order
  const severityOrder = ['critical', 'high', 'medium', 'low']
  chartData.sort((a, b) => {
    const aIndex = severityOrder.indexOf(a.severity.toLowerCase())
    const bIndex = severityOrder.indexOf(b.severity.toLowerCase())
    return aIndex - bIndex
  })

  if (chartData.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Findings by Severity</CardTitle>
        </CardHeader>
        <CardContent className="flex h-[200px] items-center justify-center">
          <p className="text-muted-foreground">No findings data available</p>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Findings by Severity</CardTitle>
      </CardHeader>
      <CardContent>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={chartData} layout="vertical">
            <CartesianGrid strokeDasharray="3 3" horizontal={false} />
            <XAxis type="number" />
            <YAxis dataKey="severity" type="category" width={80} />
            <Tooltip
              formatter={(value: number) => [value, 'Count']}
              labelFormatter={(label) => `${label} Severity`}
            />
            <Bar dataKey="count" radius={[0, 4, 4, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  )
}
