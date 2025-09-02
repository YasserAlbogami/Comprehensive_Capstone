import { type NextRequest, NextResponse } from "next/server"

interface APLocation {
  bssid: string
  lat: number
  lng: number
  name?: string
}

interface RequestPayload {
  sa: string
  minutes: number
  ap_locations: APLocation[]
}

interface RSSIPoint {
  bssid: string
  avg_rssi: number
  n: number
}

export async function POST(request: NextRequest) {
  try {
    const payload: RequestPayload = await request.json()

    // Mock RSSI points (in real implementation, this would come from database)
    const mockRSSIPoints: RSSIPoint[] = [
      { bssid: "class-ap-01", avg_rssi: -52, n: 180 },
      { bssid: "class-ap-02", avg_rssi: -64, n: 95 },
      { bssid: "class-ap-03", avg_rssi: -58, n: 120 },
    ]

    // Calculate weighted centroid based on RSSI strength
    let totalWeight = 0
    let weightedLat = 0
    let weightedLng = 0

    mockRSSIPoints.forEach((point) => {
      const ap = payload.ap_locations.find((ap) => ap.bssid === point.bssid)
      if (ap) {
        // Convert RSSI to weight (stronger signal = higher weight)
        const weight = Math.max(1, 100 - Math.abs(point.avg_rssi))

        weightedLat += ap.lat * weight
        weightedLng += ap.lng * weight
        totalWeight += weight
      }
    })

    const estimatedLat = weightedLat / totalWeight
    const estimatedLng = weightedLng / totalWeight

    // Determine confidence based on signal strength variance
    const avgRSSI = mockRSSIPoints.reduce((sum, p) => sum + Math.abs(p.avg_rssi), 0) / mockRSSIPoints.length
    const confidence = avgRSSI < 55 ? "high" : avgRSSI < 65 ? "medium" : "low"

    const response = {
      sa: payload.sa,
      estimate: {
        lat: estimatedLat,
        lng: estimatedLng,
      },
      confidence: confidence,
      points_used: mockRSSIPoints,
      raw_points: mockRSSIPoints,
    }

    return NextResponse.json(response)
  } catch {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 })
  }
}
