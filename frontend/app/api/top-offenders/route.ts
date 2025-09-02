import { type NextRequest, NextResponse } from "next/server"

interface TopOffender {
  id: number
  sourceMac: string
  vendor: string
  attackCount: number
  lastSeen: string
  firstSeen: string
  severity: "Low" | "Medium" | "High"
  channels: number[]
}

const generateTopOffenders = (timeRange: string, limit = 20): TopOffender[] => {
  const vendors = ["Apple", "Samsung", "Intel", "Broadcom", "Qualcomm", "Cisco", "Netgear", "Unknown"]
  const severities: TopOffender["severity"][] = ["Low", "Medium", "High"]

  const multiplier = timeRange === "day" ? 1 : timeRange === "week" ? 7 : 30

  return Array.from({ length: limit }, (_, i) => {
    const attackCount = Math.floor(Math.random() * 200 * multiplier) + 10
    const lastSeenMinutes = Math.floor(Math.random() * 1440) // Last 24 hours in minutes
    const channels = Array.from({ length: Math.floor(Math.random() * 5) + 1 }, () => Math.floor(Math.random() * 14) + 1)
      .filter((v, i, a) => a.indexOf(v) === i)
      .sort((a, b) => a - b)

    return {
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
      attackCount,
      lastSeen: lastSeenMinutes < 60 ? `${lastSeenMinutes} min ago` : `${Math.floor(lastSeenMinutes / 60)}h ago`,
      firstSeen: `${Math.floor(Math.random() * 7) + 1} days ago`,
      severity: severities[Math.floor(Math.random() * severities.length)],
      channels,
    }
  }).sort((a, b) => b.attackCount - a.attackCount)
}

export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams
  const timeRange = searchParams.get("range") || "day"
  const limit = Number.parseInt(searchParams.get("limit") || "20")

  if (!["day", "week", "month"].includes(timeRange)) {
    return NextResponse.json({ error: "Invalid range parameter" }, { status: 400 })
  }

  const offenders = generateTopOffenders(timeRange, limit)

  const response = {
    offenders,
    metadata: {
      range: timeRange,
      generatedAt: new Date().toISOString(),
      totalOffenders: offenders.length,
      topSeverity: offenders[0]?.severity || "Low",
    },
  }

  return NextResponse.json(response)
}
