'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { getSecurityScoreColor } from '@/lib/utils'

interface SecurityScoreProps {
  score: number
}

export function SecurityScore({ score }: SecurityScoreProps) {
  const getScoreLabel = (score: number): string => {
    if (score >= 80) return 'Excellent'
    if (score >= 60) return 'Good'
    if (score >= 40) return 'Fair'
    return 'Needs Improvement'
  }

  const getScoreDescription = (score: number): string => {
    if (score >= 80) return 'Your security posture is strong'
    if (score >= 60) return 'Some areas need attention'
    if (score >= 40) return 'Multiple security concerns detected'
    return 'Critical security issues require immediate action'
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Security Score</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center justify-center">
          <div className="relative">
            <div className="flex h-32 w-32 items-center justify-center rounded-full border-8 border-gray-100">
              <div className="text-center">
                <span className={`text-4xl font-bold ${getSecurityScoreColor(score)}`}>
                  {score.toFixed(0)}
                </span>
                <p className="text-xs text-muted-foreground">/ 100</p>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="font-medium">{getScoreLabel(score)}</span>
            <span className={getSecurityScoreColor(score)}>{score.toFixed(1)}%</span>
          </div>
          <Progress value={score} className="h-2" />
          <p className="text-xs text-muted-foreground">
            {getScoreDescription(score)}
          </p>
        </div>
      </CardContent>
    </Card>
  )
}
