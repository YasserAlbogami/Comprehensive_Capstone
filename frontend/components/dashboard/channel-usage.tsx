"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Radio } from "lucide-react"
import type { TimeRange } from "@/app/(app)/dashboard/page"

// Mock data generator
const generateChannelData = (timeRange: TimeRange) => {
  return Array.from({ length: 14 }, (_, i) => ({
    channel: i + 1,
    attacks: Math.floor(Math.random() * 100) + 5,
    utilization: Math.floor(Math.random() * 80) + 10,
  }))
}

interface ChannelUsageProps {
  timeRange: TimeRange
}

export function ChannelUsage({ timeRange }: ChannelUsageProps) {
  const channels = generateChannelData(timeRange)
  const maxAttacks = Math.max(...channels.map((c) => c.attacks))

  return (
    <Card className="glassmorphism border-cyan-500/20">
      <CardHeader>
        <CardTitle className="text-white flex items-center">
          <Radio className="w-5 h-5 mr-2 text-cyan-400" />
          Channel Usage
        </CardTitle>
        <p className="text-sm text-gray-400">Attack distribution by WiFi channel</p>
      </CardHeader>
      <CardContent>
        <div className="space-y-2">
          {channels.map((channel) => (
            <div key={channel.channel} className="flex items-center space-x-3">
              <div className="w-8 text-sm text-gray-400 font-mono">{channel.channel}</div>
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-gray-400">{channel.attacks} attacks</span>
                  <span className="text-xs text-gray-400">{channel.utilization}%</span>
                </div>
                <div className="relative">
                  {/* Attack intensity bar */}
                  <div className="w-full bg-slate-700 rounded-full h-2">
                    <div
                      className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${(channel.attacks / maxAttacks) * 100}%` }}
                    />
                  </div>
                  {/* Utilization overlay */}
                  <div className="absolute top-0 w-full bg-slate-600/50 rounded-full h-2">
                    <div
                      className="bg-yellow-500/30 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${channel.utilization}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-4 pt-3 border-t border-gray-700">
          <div className="flex items-center justify-between text-xs text-gray-400">
            <div className="flex items-center">
              <div className="w-3 h-2 bg-gradient-to-r from-cyan-500 to-blue-500 rounded mr-2"></div>
              Attacks
            </div>
            <div className="flex items-center">
              <div className="w-3 h-2 bg-yellow-500/30 rounded mr-2"></div>
              Utilization
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
