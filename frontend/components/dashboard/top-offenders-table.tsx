"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Wifi } from "lucide-react"
import type { TimeRange } from "@/app/(app)/dashboard/page"

// Mock data generator
const generateOffendersData = (timeRange: TimeRange) => {
  const vendors = ["Apple", "Samsung", "Intel", "Broadcom", "Qualcomm", "Unknown"]

  return Array.from({ length: 8 }, (_, i) => ({
    id: i + 1,
    sourceMac: `${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}`,
    vendor: vendors[Math.floor(Math.random() * vendors.length)],
    attackCount: Math.floor(Math.random() * 200) + 10,
    lastSeen: `${Math.floor(Math.random() * 60)} min ago`,
  })).sort((a, b) => b.attackCount - a.attackCount)
}

interface TopOffendersTableProps {
  timeRange: TimeRange
}

export function TopOffendersTable({ timeRange }: TopOffendersTableProps) {
  const offenders = generateOffendersData(timeRange)

  return (
    <Card className="glassmorphism border-cyan-500/20">
      <CardHeader>
        <CardTitle className="text-white flex items-center">
          <Wifi className="w-5 h-5 mr-2 text-cyan-400" />
          Top Offenders
        </CardTitle>
        <p className="text-sm text-gray-400">Most active attack sources</p>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {offenders.slice(0, 6).map((offender, index) => (
            <div
              key={offender.id}
              className="flex items-center justify-between p-3 rounded-lg bg-slate-800/50 hover:bg-slate-800/70 transition-colors"
            >
              <div className="flex items-center space-x-3">
                <div className="flex items-center justify-center w-6 h-6 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold">
                  {index + 1}
                </div>
                <div>
                  <div className="text-sm font-mono text-white">{offender.sourceMac}</div>
                  <div className="text-xs text-gray-400">{offender.vendor}</div>
                </div>
              </div>
              <div className="text-right">
                <Badge variant="outline" className="text-xs border-cyan-500/30 text-cyan-400">
                  {offender.attackCount}
                </Badge>
                <div className="text-xs text-gray-400 mt-1">{offender.lastSeen}</div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}
