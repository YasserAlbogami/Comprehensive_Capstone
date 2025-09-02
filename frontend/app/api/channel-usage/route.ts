import { type NextRequest, NextResponse } from "next/server"

interface ChannelUsage {
  channel: number
  attacks: number
  utilization: number
  dominantAttackType: string
  peakHour: number
  avgRssi: number
}

const generateChannelUsage = (timeRange: string): ChannelUsage[] => {
  const attackTypes = ["deauth", "evil_twin", "probe_flood", "beacon_flood", "krack"]
  const multiplier = timeRange === "day" ? 1 : timeRange === "week" ? 7 : 30

  return Array.from({ length: 14 }, (_, i) => {
    const channel = i + 1
    const attacks = Math.floor(Math.random() * 100 * multiplier) + 5

    // Channels 1, 6, 11 typically have higher usage (common WiFi channels)
    const isCommonChannel = [1, 6, 11].includes(channel)
    const baseUtilization = isCommonChannel ? 40 : 20
    const utilization = Math.floor(Math.random() * (80 - baseUtilization)) + baseUtilization

    return {
      channel,
      attacks,
      utilization,
      dominantAttackType: attackTypes[Math.floor(Math.random() * attackTypes.length)],
      peakHour: Math.floor(Math.random() * 24),
      avgRssi: Math.floor(Math.random() * 40) - 70, // -70 to -30 dBm
    }
  })
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const timeRange = searchParams.get("range") || "day"

  if (!["day", "week", "month"].includes(timeRange)) {
    return NextResponse.json({ error: "Invalid range parameter" }, { status: 400 })
  }

  const channelUsage = generateChannelUsage(timeRange)
  const totalAttacks = channelUsage.reduce((sum, channel) => sum + channel.attacks, 0)
  const avgUtilization = channelUsage.reduce((sum, channel) => sum + channel.utilization, 0) / channelUsage.length

  const response = {
    channels: channelUsage,
    summary: {
      totalAttacks,
      avgUtilization: Math.round(avgUtilization),
      mostActiveChannel: channelUsage.reduce((max, channel) => (channel.attacks > max.attacks ? channel : max)),
      leastActiveChannel: channelUsage.reduce((min, channel) => (channel.attacks < min.attacks ? channel : min)),
    },
    metadata: {
      range: timeRange,
      generatedAt: new Date().toISOString(),
    },
  }

  return NextResponse.json(response)
}
