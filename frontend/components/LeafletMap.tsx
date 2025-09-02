"use client"

import { useMemo } from "react"
import {
  MapContainer,
  TileLayer,
  Marker,
  Popup,
  CircleMarker,
  Polyline,
  Circle,
} from "react-leaflet"
import L from "leaflet"
import "leaflet/dist/leaflet.css"

// حل مشكلة أيقونات Leaflet مع Next.js
const DefaultIcon = L.icon({
  iconUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
  iconRetinaUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
  shadowUrl:
    "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
  shadowSize: [41, 41],
})
// @ts-ignore
L.Marker.prototype.options.icon = DefaultIcon

type LatLng = { lat: number; lng: number }

type AP = {
  bssid: string
  name?: string
  lat: number | string
  lng: number | string
}

type RSSIPoint = {
  bssid: string
  avg_rssi: number
  n: number
}

export default function LeafletMap({
  center,
  aps = [],
  points = [],
  height = 480,
  zoom = 17,
  confidence = 0, // 0..1
}: {
  center?: Partial<LatLng> | null
  aps?: AP[]
  points?: RSSIPoint[]
  height?: number
  zoom?: number
  confidence?: number
}) {
  // APs كأرقام مع تصفية القيم غير الصالحة
  const apsNorm = useMemo(() => {
    return (aps || [])
      .map((a) => ({
        ...a,
        lat: Number(a.lat),
        lng: Number(a.lng),
      }))
      .filter((a) => Number.isFinite(a.lat) && Number.isFinite(a.lng))
  }, [aps])

  // Map من BSSID → RSSI
  const rssiByBssid = useMemo(() => {
    const m = new Map<string, RSSIPoint>()
    for (const p of points || []) {
      if (p?.bssid) m.set(String(p.bssid).toUpperCase(), p)
    }
    return m
  }, [points])

  // مركز آمن
  const safeCenter: LatLng = useMemo(() => {
    const cLat = Number((center as any)?.lat)
    const cLng = Number((center as any)?.lng)
    if (Number.isFinite(cLat) && Number.isFinite(cLng)) {
      return { lat: cLat, lng: cLng }
    }
    if (apsNorm.length > 0) {
      return { lat: apsNorm[0].lat, lng: apsNorm[0].lng }
    }
    return { lat: 24.7136, lng: 46.6753 } // fallback
  }, [center, apsNorm])

  // نرسم مركز تقديري فقط لو center valid
  const showEstimated =
    Number.isFinite(Number((center as any)?.lat)) &&
    Number.isFinite(Number((center as any)?.lng))

  // نصف قطر الدائرة (متر) حسب الثقة
  const radiusMeters =
    confidence >= 0.8 ? 25 :
    confidence >= 0.5 ? 50 :
    confidence >  0   ? 100 :
                        0

  if (apsNorm.length === 0) {
    return (
      <div className="text-center text-red-400 py-10">
        لا توجد نقاط وصول لعرضها (APs). تأكّدي من /map/ap-locations.
      </div>
    )
  }

  return (
    <div className="rounded-2xl overflow-hidden border border-white/10" style={{ height }}>
      <MapContainer
        center={[safeCenter.lat, safeCenter.lng]}
        zoom={zoom}
        style={{ height: "100%", width: "100%" }}
        scrollWheelZoom
      >
        <TileLayer
          // إن حبيتي نمط داكن: https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>'
        />

        {/* APs */}
        {apsNorm.map((ap) => {
          const key = String(ap.bssid || "").toUpperCase()
          const p = rssiByBssid.get(key)
          return (
            <Marker key={ap.bssid + ap.lat + ap.lng} position={[ap.lat, ap.lng]}>
              <Popup>
                <div className="space-y-1">
                  <div><strong>{ap.name || "AP"}</strong></div>
                  <div className="text-xs">BSSID: {ap.bssid}</div>
                  {p ? (
                    <>
                      <div className="text-xs">avg RSSI: {p.avg_rssi.toFixed(1)} dBm</div>
                      <div className="text-xs">samples: {p.n}</div>
                    </>
                  ) : (
                    <div className="text-xs text-gray-500">لا توجد قياسات RSSI لهذه النقطة</div>
                  )}
                </div>
              </Popup>
            </Marker>
          )
        })}

        {/* مركز المصدر */}
        {showEstimated && (
          <CircleMarker
            center={[Number((center as any).lat), Number((center as any).lng)]}
            radius={10}
            pathOptions={{ weight: 2 }}
          >
            <Popup>
              <div className="space-y-1">
                <div><strong>Estimated Source</strong></div>
                <div className="text-xs">
                  lat: {Number((center as any).lat).toFixed(6)}, lng: {Number((center as any).lng).toFixed(6)}
                </div>
              </div>
            </Popup>
          </CircleMarker>
        )}

        {/* دائرة نطاق الشك */}
        {showEstimated && radiusMeters > 0 && (
          <Circle
            center={[Number((center as any).lat), Number((center as any).lng)]}
            radius={radiusMeters}
            pathOptions={{ weight: 1, fillOpacity: 0.15 }}
          />
        )}

        {/* خطوط من المركز → APs اللي لها RSSI */}
        {showEstimated &&
          apsNorm.map((ap) => {
            const p = rssiByBssid.get(String(ap.bssid || "").toUpperCase())
            if (!p) return null
            return (
              <Polyline
                key={"ln-" + ap.bssid}
                positions={[
                  [Number((center as any).lat), Number((center as any).lng)],
                  [ap.lat, ap.lng],
                ]}
                pathOptions={{ weight: 1.5, opacity: 0.7 }}
              />
            )
          })}
      </MapContainer>
    </div>
  )
}
