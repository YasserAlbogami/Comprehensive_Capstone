"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts"
import { attackColors } from "@/lib/colors"
import type { TimeRange } from "@/app/(app)/dashboard/page"

// Mock data generator
const generateTimelineData = (timeRange: TimeRange) => {
  const hours = timeRange === "day" ? 24 : timeRange === "week" ? 7 * 24 : 30 * 24
  const step = timeRange === "day" ? 1 : timeRange === "week" ? 24 : 24 * 7

  return Array.from({ length: Math.floor(hours / step) }, (_, i) => {
    const data: any = { time: i }
    Object.keys(attackColors).forEach((type) => {
      data[type] = Math.floor(Math.random() * 20) + 5
    })
    return data
  })
}

interface TimelineChartProps {
  timeRange: TimeRange
}

export function TimelineChart({ timeRange }: TimelineChartProps) {
  const [hiddenLines, setHiddenLines] = useState<Set<string>>(new Set())
  const data = generateTimelineData(timeRange)

  const toggleLine = (dataKey: string) => {
    const newHidden = new Set(hiddenLines)
    if (newHidden.has(dataKey)) {
      newHidden.delete(dataKey)
    } else {
      newHidden.add(dataKey)
    }
    setHiddenLines(newHidden)
  }

  const formatXAxisLabel = (tickItem: number) => {
    if (timeRange === "day") return `${tickItem}:00`
    if (timeRange === "week") return `Day ${tickItem + 1}`
    return `Week ${tickItem + 1}`
  }

  return (
    <Card className="glassmorphism border-cyan-500/20">
      <CardHeader>
        <CardTitle className="text-white">Attack Timeline</CardTitle>
        <p className="text-sm text-gray-400">Attack frequency over time</p>
      </CardHeader>
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="time" stroke="#9CA3AF" tickFormatter={formatXAxisLabel} />
              <YAxis stroke="#9CA3AF" />
              <Tooltip
                contentStyle={{
                  backgroundColor: "rgba(15, 23, 42, 0.9)",
                  border: "1px solid rgba(34, 211, 238, 0.3)",
                  borderRadius: "8px",
                }}
                labelStyle={{ color: "#E5E7EB" }}
              />
              <Legend onClick={(e) => toggleLine(e.dataKey as string)} wrapperStyle={{ cursor: "pointer" }} />
              {Object.entries(attackColors).map(([type, color]) => (
                <Line
                  key={type}
                  type="monotone"
                  dataKey={type}
                  stroke={color}
                  strokeWidth={2}
                  dot={false}
                  hide={hiddenLines.has(type)}
                  name={type.replace("_", " ")}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}
