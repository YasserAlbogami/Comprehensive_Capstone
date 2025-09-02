"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { attackColors, attackLabels, type AttackType } from "@/lib/colors"
import { LineChart, Line, ResponsiveContainer } from "recharts"
import type { TimeRange } from "@/app/(app)/dashboard/page"
import { useMemo } from "react"

// Mock data generator
const generateSparklineData = () => {
  return Array.from({ length: 24 }, (_, i) => ({
    hour: i,
    value: Math.floor(Math.random() * 50) + 10,
  }))
}

const generateMetricData = (timeRange: TimeRange) => {
  const multiplier = timeRange === "day" ? 1 : timeRange === "week" ? 7 : 30

  return Object.keys(attackColors).map((type) => ({
    type: type as AttackType,
    count: Math.floor(Math.random() * 100 * multiplier) + 10,
    change: Math.floor(Math.random() * 40) - 20, // -20 to +20
    sparklineData: generateSparklineData(),
  }))
}

interface MetricCardsProps {
  timeRange: TimeRange
}

export function MetricCards({ timeRange }: MetricCardsProps) {
  const metrics = useMemo(() => generateMetricData(timeRange), [timeRange])

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {metrics.map((metric) => (
        <Card key={metric.type} className="glassmorphism border-cyan-500/20 hover:border-cyan-500/40 transition-all">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium text-gray-300">
                {attackLabels[metric.type]}
              </CardTitle>
              <Badge
                className="text-xs px-2 py-1"
                style={{
                  backgroundColor: `${attackColors[metric.type]}20`,
                  color: attackColors[metric.type],
                  borderColor: `${attackColors[metric.type]}40`,
                }}
              >
                {metric.change > 0 ? "+" : ""}
                {metric.change}%
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex items-end justify-between">
              <div>
                <div className="text-2xl font-bold text-white">{metric.count.toLocaleString()}</div>
                <p className="text-xs text-gray-400 mt-1">
                  {timeRange === "day" ? "Today" : timeRange === "week" ? "This week" : "This month"}
                </p>
              </div>
              <div className="w-16 h-8">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={metric.sparklineData}>
                    <Line
                      type="monotone"
                      dataKey="value"
                      stroke={attackColors[metric.type]}
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
