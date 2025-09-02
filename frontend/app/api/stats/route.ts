import { type NextRequest, NextResponse } from "next/server"
import { attackColors, type AttackType } from "@/lib/colors"

// Mock data generators
const generateAttackTotals = (timeRange: string) => {
  const multiplier = timeRange === "day" ? 1 : timeRange === "week" ? 7 : 30
  const totals: Record<AttackType, number> = {} as Record<AttackType, number>

  Object.keys(attackColors).forEach((type) => {
    totals[type as AttackType] = Math.floor(Math.random() * 100 * multiplier) + 10
  })

  return totals
}

const generateTimeSeriesData = (timeRange: string) => {
  const hours = timeRange === "day" ? 24 : timeRange === "week" ? 7 * 24 : 30 * 24
  const step = timeRange === "day" ? 1 : timeRange === "week" ? 24 : 24 * 7
  const points = Math.floor(hours / step)

  return Array.from({ length: points }, (_, i) => {
    const data: any = {
      time: timeRange === "day" ? `${i}:00` : timeRange === "week" ? `Day ${i + 1}` : `Week ${i + 1}`,
      timestamp: Date.now() - (points - i) * step * 60 * 60 * 1000,
    }

    Object.keys(attackColors).forEach((type) => {
      data[type] = Math.floor(Math.random() * 20) + 5
    })

    return data
  })
}

const generatePeakHoursData = (timeRange: string) => {
  return Array.from({ length: 24 }, (_, hour) => {
    const data: any = {
      hour: `${hour}:00`,
      hourNumber: hour,
    }

    Object.keys(attackColors).forEach((type) => {
      // Simulate peak hours (9-17 and 19-23)
      const isPeakHour = (hour >= 9 && hour <= 17) || (hour >= 19 && hour <= 23)
      const baseValue = isPeakHour ? 15 : 5
      data[type] = Math.floor(Math.random() * baseValue) + 2
    })

    return data
  })
}

const generateHeatmapData = (timeRange: string) => {
  const days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

  return days.map((day, dayIndex) => ({
    day,
    dayIndex,
    hours: Array.from({ length: 24 }, (_, hour) => ({
      hour,
      intensity: Math.floor(Math.random() * 100),
      attacks: Math.floor(Math.random() * 50) + 1,
    })),
  }))
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const range = searchParams.get("range") || "day"

  // Validate range parameter
  if (!["day", "week", "month"].includes(range)) {
    return NextResponse.json({ error: "Invalid range parameter" }, { status: 400 })
  }

  const stats = {
    totals: generateAttackTotals(range),
    series: generateTimeSeriesData(range),
    peakHours: generatePeakHoursData(range),
    heatmap: generateHeatmapData(range),
    metadata: {
      range,
      generatedAt: new Date().toISOString(),
      totalEvents: Object.values(generateAttackTotals(range)).reduce((sum, count) => sum + count, 0),
    },
  }

  return NextResponse.json(stats)
}
