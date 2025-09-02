"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Activity, Cpu, Wifi } from "lucide-react"

// Mock data
const systemData = {
  status: "Healthy" as "Healthy" | "Learning" | "Degraded",
  packetsPerSec: 1247,
  cpuUsage: 23,
  memoryUsage: 67,
  uptime: "7d 14h 32m",
}

export function SystemStatus() {
  const getStatusColor = (status: string) => {
    switch (status) {
      case "Healthy":
        return "bg-green-500/20 text-green-400 border-green-500/30"
      case "Learning":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
      case "Degraded":
        return "bg-red-500/20 text-red-400 border-red-500/30"
      default:
        return "bg-gray-500/20 text-gray-400 border-gray-500/30"
    }
  }

  return (
    <Card className="glassmorphism border-cyan-500/20">
      <CardHeader>
        <CardTitle className="text-white flex items-center">
          <Activity className="w-5 h-5 mr-2 text-cyan-400" />
          System Status
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Status Badge */}
        <div className="flex items-center justify-between">
          <span className="text-sm text-gray-400">Status</span>
          <Badge className={getStatusColor(systemData.status)}>{systemData.status}</Badge>
        </div>

        {/* Packets per second gauge */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400 flex items-center">
              <Wifi className="w-4 h-4 mr-1" />
              Packets/sec
            </span>
            <span className="text-lg font-bold text-cyan-400">{systemData.packetsPerSec.toLocaleString()}</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${Math.min((systemData.packetsPerSec / 2000) * 100, 100)}%` }}
            />
          </div>
        </div>

        {/* Resource usage */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400 flex items-center">
              <Cpu className="w-4 h-4 mr-1" />
              CPU Usage
            </span>
            <span className="text-sm text-white">{systemData.cpuUsage}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-1.5">
            <div
              className="bg-cyan-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${systemData.cpuUsage}%` }}
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400">Memory Usage</span>
            <span className="text-sm text-white">{systemData.memoryUsage}%</span>
          </div>
          <div className="w-full bg-slate-700 rounded-full h-1.5">
            <div
              className="bg-blue-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${systemData.memoryUsage}%` }}
            />
          </div>
        </div>

        {/* Uptime */}
        <div className="pt-2 border-t border-gray-700">
          <div className="flex items-center justify-between">
            <span className="text-sm text-gray-400">Uptime</span>
            <span className="text-sm text-white font-mono">{systemData.uptime}</span>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
