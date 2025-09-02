"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts"
import { attackColors } from "@/lib/colors"
import type { TimeRange } from "@/app/(app)/dashboard/page"

// Mock data generator
const generatePeakHoursData = (timeRange: TimeRange) => {
  return Array.from({ length: 24 }, (_, hour) => {
    const data: any = { hour: `${hour}:00` }
    Object.keys(attackColors).forEach((type) => {
      data[type] = Math.floor(Math.random() * 15) + 2
    })
    return data
  })
}

interface PeakHoursChartProps {
  timeRange: TimeRange
}

export function PeakHoursChart({ timeRange }: PeakHoursChartProps) {
  const data = generatePeakHoursData(timeRange)

  return (
    <Card className="glassmorphism border-cyan-500/20">
      <CardHeader>
        <CardTitle className="text-white">Peak Hours Analysis</CardTitle>
        <p className="text-sm text-gray-400">Attack distribution by hour</p>
      </CardHeader>
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="hour" stroke="#9CA3AF" interval={2} />
              <YAxis stroke="#9CA3AF" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "rgba(15, 23, 42, 0.9)",
                  border: "1px solid rgba(34, 211, 238, 0.3)",
                  borderRadius: "8px",
                }}
                labelStyle={{ color: "#E5E7EB" }}
              />
              {Object.entries(attackColors).map(([type, color]) => (
                <Bar key={type} dataKey={type} stackId="attacks" fill={color} name={type.replace("_", " ")} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}
