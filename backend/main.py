# main.py
from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, text
from sqlalchemy.orm import Session

# ✅ use the single DB wiring from db.py
from db import get_db, Packet

from packet_query import packet_ask
from schemas import (
    DetectorConfig,
    DetectorStatus,
    RSSIPoint,
    SourceRSSIResponse,
)

# Detector (fallback dummy if not importable)
try:
    from detector import detector  # type: ignore
except Exception:
    class _DummyDetector:
        def start(self, cfg: DetectorConfig):
            raise RuntimeError("Detector module is not available.")
        def status(self):
            return {"status": "unavailable"}
    detector = _DummyDetector()  # type: ignore

# PDF
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ──────────────────────────────────────────────────────────────────────────────
# App & CORS
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
# Mapping you use across the app
TYPE_MAP_DB_TO_FRONT = {
    "Deauth": "deauth",
    "SSDP": "ssdp",
    "Evil_Twin": "evil_twin",
    "(Re)Assoc": "reassoc",
    "RogueAP": "rogueap",
    "Krack": "krack",
}
FRONT_TYPES = ["deauth", "ssdp", "evil_twin", "reassoc", "rogueap", "krack"]

def _since_dt(days: int) -> datetime:
    # Return an aware datetime (UTC)
    return datetime.now(timezone.utc) - timedelta(days=days)

# Tiny TTL cache for /ask
class TTLCache:
    def __init__(self, maxsize: int = 200, ttl_seconds: int = 600):
        self.store: OrderedDict[str, Any] = OrderedDict()
        self.maxsize = maxsize
        self.ttl = timedelta(seconds=ttl_seconds)

    def _purge_expired(self):
        now = datetime.utcnow()
        drop = [k for k, v in self.store.items() if now - v["ts"] > self.ttl]
        for k in drop:
            del self.store[k]

    def get(self, key: str):
        self._purge_expired()
        if key in self.store:
            val = self.store.pop(key)
            self.store[key] = val
            return val["data"]
        return None

    def set(self, key: str, value: Any):
        self._purge_expired()
        if key in self.store:
            self.store.pop(key)
        elif len(self.store) >= self.maxsize:
            self.store.popitem(last=False)
        self.store[key] = {"data": value, "ts": datetime.utcnow()}

cache = TTLCache()
SESSION_MEMORY: Dict[str, List[Dict[str, str]]] = {}
MAX_TURNS = 5

def _norm_key(text: str) -> str:
    return hashlib.sha256(text.strip().lower().encode("utf-8")).hexdigest()

def _build_context(session_id: str) -> str:
    turns = SESSION_MEMORY.get(session_id, [])
    if not turns:
        return ""
    return "\n\n".join(f"Q: {t['q']}\nA: {t['a']}" for t in turns[-MAX_TURNS:])

# ──────────────────────────────────────────────────────────────────────────────
# Packets / Attacks
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/attacks")
def get_all_packets(
    db: Session = Depends(get_db),
    limit: int = Query(5000, ge=1, le=100000),
    offset: int = Query(0, ge=0),
):
    """
    Raw dump of packets table with pagination.
    Usage: /attacks?limit=5000&offset=0
    """
    sql = text("SELECT * FROM packets ORDER BY id DESC LIMIT :limit OFFSET :offset")
    rows = db.execute(sql, {"limit": limit, "offset": offset}).mappings().all()
    #print(rows)
    return [dict(r) for r in rows]

@app.get("/packets/count")
def packets_count(db: Session = Depends(get_db)):
    n = db.execute(text("SELECT COUNT(*) AS c FROM packets")).mappings().first()["c"]
    return {"count": int(n)}

@app.get("/attacks/analysis")
def read_attack_analysis(db: Session = Depends(get_db)):
    """
    Count by predicted_label (DB labels), but return only known types:
    Deauth, SSDP, Evil_Twin, (Re)Assoc, RogueAP, Krack
    """
    rows = (
        db.query(Packet.predicted_label, func.count(Packet.id))
          .filter(Packet.predicted_label.isnot(None))
          .group_by(Packet.predicted_label)
          .all()
    )
    result = {k: 0 for k in ["Deauth", "SSDP", "Evil_Twin", "(Re)Assoc", "RogueAP", "Krack"]}
    for db_label, cnt in rows:
        if db_label in result:
            result[db_label] = int(cnt)
    return result

@app.get("/top-offenders")
def top_offenders(db: Session = Depends(get_db)):
    """
    Top sources by src_mac (was wlan_sa).
    """
    rows = (
        db.query(Packet.src_mac, func.count(Packet.id))
          .group_by(Packet.src_mac)
          .order_by(func.count(Packet.id).desc())
          .all()
    )
    return [{"wlan_sa": mac, "count": int(n)} for mac, n in rows if mac]

@app.get("/channel-usage")
def channel_usage(db: Session = Depends(get_db)):
    """
    Channel usage by channel_freq (was radiotap_channel_freq).
    """
    rows = (
        db.query(Packet.channel_freq, func.count(Packet.id))
          .group_by(Packet.channel_freq)
          .order_by(func.count(Packet.id).desc())
          .all()
    )
    return [{"channel_freq": int(freq), "count": int(c)} for (freq, c) in rows if freq is not None]

@app.get("/heatmap-attack")
def heatmap_attack(db: Session = Depends(get_db)):
    """
    Build a simple week x hour heatmap from ts (aware datetime preferred).
    Frontend earlier expected Sun..Sat order.
    """
    # We'll accumulate in Mon..Sun then reorder to Sun..Sat for UI compatibility
    day_names_mon_first = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    buckets = {d: [{"hour": h, "intensity": 0} for h in range(24)] for d in day_names_mon_first}

    for (ts,) in db.query(Packet.ts).all():
        if not ts:
            continue
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        day = day_names_mon_first[dt.weekday()]  # Mon=0
        buckets[day][dt.hour]["intensity"] += 1

    # Reorder to Sun..Sat if your front expects that
    order = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    return [{"day": d, "hours": buckets[d]} if d in buckets else {"day": d, "hours": [{"hour": h, "intensity": 0} for h in range(24)]} for d in order]

# ──────────────────────────────────────────────────────────────────────────────
# Run detector
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/detector/start", response_model=DetectorStatus)
def start_detector(cfg: DetectorConfig):
    try:
        detector.start(cfg)
        return detector.status()
    except RuntimeError as e:
        raise HTTPException(status_code=409, detail=str(e))

# ──────────────────────────────────────────────────────────────────────────────
# RAG /ask
# ──────────────────────────────────────────────────────────────────────────────
class AskPayload(BaseModel):
    question: str
    session_id: Optional[str] = None

@app.post("/ask")
def ask(payload: AskPayload):
    session_id = payload.session_id or "default-session"
    context = _build_context(session_id)
    if context:
        full_q = (
            "Use the prior short transcript as conversational context ONLY if needed.\n\n"
            f"Transcript (most-recent first):\n{context}\n\n"
            f"Now the new user question: {payload.question.strip()}"
        )
    else:
        full_q = payload.question.strip()

    ck = _norm_key(session_id + "||" + full_q)
    cached = cache.get(ck)
    if cached:
        return {"cached": True, **cached}

    result = packet_ask(full_q)

    compact_answer = (result.get("answer") or "")[:800]
    SESSION_MEMORY.setdefault(session_id, []).append({"q": payload.question.strip(), "a": compact_answer})
    if len(SESSION_MEMORY[session_id]) > MAX_TURNS:
        SESSION_MEMORY[session_id] = SESSION_MEMORY[session_id][-MAX_TURNS:]

    resp = {
        "mode": result.get("mode"),
        "sql": result.get("sql"),
        "answer": result.get("answer"),
        "cols": result.get("cols"),
        "rows": result.get("rows"),
        "error": result.get("error"),
    }
    cache.set(ck, resp)
    return {"cached": False, **resp}

# ──────────────────────────────────────────────────────────────────────────────
# Map / AP estimation
# ──────────────────────────────────────────────────────────────────────────────
@app.get("/map/ap-locations")
def ap_locations():
    # Demo APs; swap with real inventory if you have it.
    return [
        {"bssid": "AA:AA:AA:AA:AA:01", "name": "AP-1", "lat": 24.7136, "lng": 46.6753},
        {"bssid": "AA:AA:AA:AA:AA:02", "name": "AP-2", "lat": 24.7139, "lng": 46.6758},
        {"bssid": "AA:AA:AA:AA:AA:03", "name": "AP-3", "lat": 24.7142, "lng": 46.6751},
    ]

@app.get("/map/source-rssi", response_model=SourceRSSIResponse)
def source_rssi(sa: str, minutes: int = 10, db: Session = Depends(get_db)):
    """
    Average RSSI (signal_dbm) per BSSID for frames from source MAC (src_mac).
    Time window is last `minutes`.
    """
    lower_bound_dt = datetime.fromtimestamp(time.time() - minutes * 60, tz=timezone.utc)
    rows = (
        db.query(
            Packet.bssid.label("bssid"),
            func.avg(Packet.signal_dbm).label("avg_rssi"),
            func.count(Packet.id).label("n"),
        )
        .filter(Packet.src_mac == sa)
        .filter(Packet.ts >= lower_bound_dt)
        .group_by(Packet.bssid)
        .all()
    )
    points = [
        RSSIPoint(bssid=str(r.bssid or ""), avg_rssi=float(r.avg_rssi or -90.0), n=int(r.n or 0))
        for r in rows if r.bssid
    ]
    return SourceRSSIResponse(sa=sa, points=points)

@app.post("/map/estimate-origin")
def estimate_origin(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Estimate a rough origin point by weighted centroid of AP locations,
    weighted by |RSSI| strength from the given source address (src_mac).
    body:
    {
      "sa": "AA:BB:CC:DD:EE:FF",
      "minutes": 10,
      "ap_locations": [{"bssid":"...","lat":..,"lng":..}, ...]
    }
    """
    sa = str(payload.get("sa") or "")
    minutes = int(payload.get("minutes") or 10)
    ap_locations = payload.get("ap_locations") or []
    if not sa or not ap_locations:
        return {"detail": "Missing sa or ap_locations"}

    lower_bound_dt = datetime.fromtimestamp(time.time() - minutes * 60, tz=timezone.utc)
    rows = (
        db.query(
            Packet.bssid.label("bssid"),
            func.avg(Packet.signal_dbm).label("avg_rssi"),
            func.count(Packet.id).label("n"),
        )
        .filter(Packet.src_mac == sa)
        .filter(Packet.ts >= lower_bound_dt)
        .group_by(Packet.bssid)
        .all()
    )
    rssi_by_bssid = {str(r.bssid): float(r.avg_rssi or -90.0) for r in rows if r.bssid}

    used = []
    for ap in ap_locations:
        bssid = str(ap.get("bssid") or "")
        if not bssid or bssid not in rssi_by_bssid:
            continue
        lat = float(ap.get("lat"))
        lng = float(ap.get("lng"))
        rssi = rssi_by_bssid[bssid]
        w = 1.0 / max(1.0, abs(rssi) + 1.0)  # simple weighting by signal strength
        used.append((lat, lng, w))

    if not used:
        return {
            "sa": sa, "method": "weighted-centroid", "used": 0, "center": None,
            "note": "No matching RSSI/AP pairs in the selected window.",
        }

    sw = sum(w for _, _, w in used)
    lat = sum(lat * w for lat, _, w in used) / sw
    lng = sum(lng * w for _, lng, w in used) / sw
    return {"sa": sa, "method": "weighted-centroid", "used": len(used), "center": {"lat": lat, "lng": lng}}

# ──────────────────────────────────────────────────────────────────────────────
# Reports (summary + PDF export)
# ──────────────────────────────────────────────────────────────────────────────
class ReportSummary(BaseModel):
    period: str
    totals: Dict[str, int]
    summary: Dict[str, Any]

def compute_summary(db: Session, days: int = 30) -> ReportSummary:
    lb_dt = _since_dt(days)

    # counts by predicted_label within window
    rows = (
        db.query(Packet.predicted_label, func.count(Packet.id))
          .filter(Packet.ts >= lb_dt)
          .group_by(Packet.predicted_label)
          .all()
    )

    totals = {k: 0 for k in FRONT_TYPES}
    other = 0
    for db_label, cnt in rows:
        key = TYPE_MAP_DB_TO_FRONT.get(db_label, None)
        if key in totals:
            totals[key] += int(cnt)
        else:
            other += int(cnt)
    totals["other"] = other

    # peak hour (UTC)
    hours = [0] * 24
    for (ts,) in db.query(Packet.ts).filter(Packet.ts >= lb_dt).all():
        if not ts:
            continue
        dt = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        hours[dt.hour] += 1
    peak_hour = max(range(24), key=lambda h: hours[h]) if any(hours) else 0

    # unique sources in window
    unique_sources = (
        db.query(func.count(func.distinct(Packet.src_mac)))
          .filter(Packet.ts >= lb_dt)
          .scalar() or 0
    )

    total_attacks = sum(totals.values())
    most = max(totals, key=totals.get) if total_attacks else "other"

    return ReportSummary(
        period=f"Last {days} day(s)",
        totals=totals,
        summary={
            "totalAttacks": total_attacks,
            "mostFrequentType": most,
            "peakHour": peak_hour,
            "uniqueSources": int(unique_sources),
        },
    )

@app.get("/reports/summary")
def get_report_summary(days: int = 30, db: Session = Depends(get_db)):
    data = compute_summary(db, days=days)
    return data.model_dump()

class ReportExportPayload(BaseModel):
    days: int = 30

@app.post("/reports/export")
def export_pdf(payload: ReportExportPayload, db: Session = Depends(get_db)):
    data = compute_summary(db, days=payload.days)

    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 50
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(40, y, "HawkShield – Attack Report")
    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(40, y, f"Period: {data.period}")
    y -= 30

    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Totals by Type")
    y -= 16
    pdf.setFont("Helvetica", 10)
    for k in ["deauth", "ssdp", "evil_twin", "reassoc", "rogueap", "krack", "other"]:
        line = f"{k:12s} : {data.totals.get(k, 0)}"
        pdf.drawString(60, y, line)
        y -= 14

    y -= 10
    pdf.setFont("Helvetica-Bold", 12)
    pdf.drawString(40, y, "Summary")
    y -= 16
    pdf.setFont("Helvetica", 10)
    pdf.drawString(60, y, f"Total Attacks     : {data.summary['totalAttacks']}")
    y -= 14
    pdf.drawString(60, y, f"Most Frequent     : {data.summary['mostFrequentType']}")
    y -= 14
    pdf.drawString(60, y, f"Peak Hour (UTC)   : {data.summary['peakHour']}:00")
    y -= 14
    pdf.drawString(60, y, f"Unique Sources    : {data.summary['uniqueSources']}")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)

    filename = f"hawkshield_report_{payload.days}d.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(buffer, media_type="application/pdf", headers=headers)

# Optional stub for mail
@app.post("/reports/email")
def send_email_stub():
    return JSONResponse({"ok": True, "note": "Email sending is not implemented; frontend should use mailto:"})
