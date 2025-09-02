import { NextResponse } from "next/server"

export async function GET() {
  // Mock RSSI data for an attacker
  const mockData = {
    sa: "attacker:aa:bb:cc:dd:ee:ff",
    points: [
      {
        bssid: "class-ap-01",
        avg_rssi: -52,
        n: 180,
      },
      {
        bssid: "class-ap-02",
        avg_rssi: -64,
        n: 95,
      },
      {
        bssid: "class-ap-03",
        avg_rssi: -58,
        n: 120,
      },
    ],
  }

  return NextResponse.json(mockData)
}
