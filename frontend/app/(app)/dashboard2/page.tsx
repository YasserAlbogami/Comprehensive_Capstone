"use client"

import { useState } from "react"
import dynamic from "next/dynamic"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import type { TimeRange } from "@/lib/types"

// Dynamically import components with SSR disabled to prevent hydration issues
const MetricCards = dynamic(() => import("@/components/dashboard/metric-cards").then(mod => ({ default: mod.MetricCards })), { ssr: false })
const TimelineChart = dynamic(() => import("@/components/dashboard/timeline-chart").then(mod => ({ default: mod.TimelineChart })), { ssr: false })
const PeakHoursChart = dynamic(() => import("@/components/dashboard/peak-hours-chart").then(mod => ({ default: mod.PeakHoursChart })), { ssr: false })
const AttackHeatmap = dynamic(() => import("@/components/dashboard/attack-heatmap").then(mod => ({ default: mod.AttackHeatmap })), { ssr: false })
const TopOffendersTable = dynamic(() => import("@/components/dashboard/top-offenders-table").then(mod => ({ default: mod.TopOffendersTable })), { ssr: false })
const ChannelUsage = dynamic(() => import("@/components/dashboard/channel-usage").then(mod => ({ default: mod.ChannelUsage })), { ssr: false })
const LiveFeed = dynamic(() => import("@/components/dashboard/live-feed").then(mod => ({ default: mod.LiveFeed })), { ssr: false })
const SystemStatus = dynamic(() => import("@/components/dashboard/system-status").then(mod => ({ default: mod.SystemStatus })), { ssr: false })
const MapTrilateration = dynamic(() => import("@/components/MapTrilateration"), { ssr: false })

export default function DashboardPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("day")

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header with Time Range Filter */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="text-gray-400 mt-1">Real-time WiFi intrusion monitoring and analytics</p>
        </div>
        <Select value={timeRange} onValueChange={(value: TimeRange) => setTimeRange(value)}>
          <SelectTrigger className="w-32 glassmorphism border-cyan-500/30">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="glassmorphism border-cyan-500/30">
            <SelectItem value="day">Day</SelectItem>
            <SelectItem value="week">Week</SelectItem>
            <SelectItem value="month">Month</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Metric Cards */}
      <MetricCards timeRange={timeRange} />

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TimelineChart timeRange={timeRange} />
        <PeakHoursChart timeRange={timeRange} />
      </div>

      {/* Secondary Widgets */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AttackHeatmap timeRange={timeRange} />
        </div>
        <SystemStatus />
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <TopOffendersTable timeRange={timeRange} />
        <ChannelUsage timeRange={timeRange} />
        <LiveFeed />
      </div>

      <div className="grid grid-cols-1 gap-6">
        <MapTrilateration />
      </div>
    </div>
  )
}
