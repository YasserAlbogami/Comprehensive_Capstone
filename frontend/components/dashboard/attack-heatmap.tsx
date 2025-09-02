"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { TimeRange } from "@/app/(app)/dashboard/page"

// Mock data generator
const generateHeatmapData = (timeRange: TimeRange) => {
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
  const hours = Array.from({ length: 24 }, (_, i) => i)

  return days.map((day) => ({
    day,
    hours: hours.map((hour) => ({
      hour,
      intensity: Math.floor(Math.random() * 100),
    })),
  }))
}

interface AttackHeatmapProps {
  timeRange: TimeRange
}

export function AttackHeatmap({ timeRange }: AttackHeatmapProps) {
  const data = generateHeatmapData(timeRange)
  console.log(data)

  const getIntensityColor = (intensity: number) => {
    if (intensity < 20) return "bg-slate-800"
    if (intensity < 40) return "bg-blue-900/50"
    if (intensity < 60) return "bg-blue-700/70"
    if (intensity < 80) return "bg-cyan-600/80"
    return "bg-cyan-400"
  }

  return (
    <Card className="glassmorphism border-cyan-500/20">
      <CardHeader>
        <CardTitle className="text-white">Attack Intensity Heatmap</CardTitle>
        <p className="text-sm text-gray-400">Day × Hour attack patterns</p>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {/* Hour labels */}
          <div className="flex items-center">
            <div className="w-12"></div>
            <div className="flex-1 grid grid-cols-24 gap-1 text-xs text-gray-400">
              {Array.from({ length: 24 }, (_, i) => (
                <div key={i} className="text-center">
                  {i % 4 === 0 ? i : ""}
                </div>
              ))}
            </div>
          </div>

          {/* Heatmap grid */}
          {data.map((dayData) => (
            <div key={dayData.day} className="flex items-center">
              <div className="w-12 text-sm text-gray-400 font-medium">{dayData.day}</div>
              <div className="flex-1 grid grid-cols-24 gap-1">
                {dayData.hours.map((hourData) => (
                  <div
                    key={hourData.hour}
                    className={`aspect-square rounded-sm ${getIntensityColor(hourData.intensity)} hover:ring-1 hover:ring-cyan-400 transition-all cursor-pointer`}
                    title={`${dayData.day} ${hourData.hour}:00 - ${hourData.intensity} attacks`}
                  />
                ))}
              </div>
            </div>
          ))}

          {/* Legend */}
          <div className="flex items-center justify-center space-x-2 mt-4 text-xs text-gray-400">
            <span>Less</span>
            <div className="flex space-x-1">
              <div className="w-3 h-3 bg-slate-800 rounded-sm"></div>
              <div className="w-3 h-3 bg-blue-900/50 rounded-sm"></div>
              <div className="w-3 h-3 bg-blue-700/70 rounded-sm"></div>
              <div className="w-3 h-3 bg-cyan-600/80 rounded-sm"></div>
              <div className="w-3 h-3 bg-cyan-400 rounded-sm"></div>
            </div>
            <span>More</span>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
