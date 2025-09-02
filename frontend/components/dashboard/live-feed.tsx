"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Activity, AlertTriangle } from "lucide-react"
import { attackColors, attackLabels, type AttackType } from "@/lib/colors"

interface LiveEvent {
  id: string
  timestamp: Date
  type: AttackType
  sourceMac: string
  severity: "Low" | "Medium" | "High"
  channel: number
}

// Mock data generator
const generateLiveEvent = (): LiveEvent => {
  const types = Object.keys(attackColors) as AttackType[]
  const severities: LiveEvent["severity"][] = ["Low", "Medium", "High"]

  return {
    id: Math.random().toString(36).substr(2, 9),
    timestamp: new Date(),
    type: types[Math.floor(Math.random() * types.length)],
    sourceMac: `${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:${Math.floor(Math.random() * 256)
      .toString(16)
      .padStart(2, "0")}:xx:xx:xx`,
    severity: severities[Math.floor(Math.random() * severities.length)],
    channel: Math.floor(Math.random() * 14) + 1,
  }
}

export function LiveFeed() {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [isClient, setIsClient] = useState(false)

  useEffect(() => {
    setIsClient(true)
    
    // Initialize with some events
    const initialEvents = Array.from({ length: 5 }, () => generateLiveEvent())
    setEvents(initialEvents)

    // Add new events every 3-8 seconds
    const interval = setInterval(
      () => {
        const newEvent = generateLiveEvent()
        setEvents((prev) => [newEvent, ...prev.slice(0, 9)]) // Keep only last 10 events
      },
      Math.random() * 5000 + 3000,
    )

    return () => clearInterval(interval)
  }, [])

  const getSeverityColor = (severity: LiveEvent["severity"]) => {
    switch (severity) {
      case "High":
        return "bg-red-500/20 text-red-400 border-red-500/30"
      case "Medium":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
      case "Low":
        return "bg-green-500/20 text-green-400 border-green-500/30"
    }
  }

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  }

  return (
    <Card className="glassmorphism border-cyan-500/20">
      <CardHeader>
        <CardTitle className="text-white flex items-center">
          <Activity className="w-5 h-5 mr-2 text-cyan-400" />
          Live Feed
          <div className="ml-2 w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
        </CardTitle>
        <p className="text-sm text-gray-400">Real-time attack detection</p>
      </CardHeader>
      <CardContent>
        <div className="space-y-3 max-h-80 overflow-y-auto">
          {!isClient ? (
            <div className="text-center text-gray-400 py-4">Loading live feed...</div>
          ) : (
            events.map((event) => (
              <div
                key={event.id}
                className="flex items-start space-x-3 p-3 rounded-lg bg-slate-800/30 hover:bg-slate-800/50 transition-colors"
              >
                <div className="flex-shrink-0 mt-1">
                  <AlertTriangle className="w-4 h-4" style={{ color: attackColors[event.type] }} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-medium" style={{ color: attackColors[event.type] }}>
                      {attackLabels[event.type]}
                    </span>
                    <Badge className={`text-xs ${getSeverityColor(event.severity)}`}>{event.severity}</Badge>
                  </div>
                  <div className="text-xs text-gray-400 mt-1">
                    <div className="font-mono">{event.sourceMac}</div>
                    <div className="flex items-center justify-between mt-1">
                      <span>Ch {event.channel}</span>
                      <time dateTime={event.timestamp.toISOString()} suppressHydrationWarning>
                        {formatTime(event.timestamp)}
                      </time>
                    </div>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  )
}
