# schemas.py
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class RAGDoc(BaseModel):
    title: Optional[str] = None
    text: str
    tags: Optional[str] = None

class RAGAddDocsRequest(BaseModel):
    docs: List[RAGDoc]

class RAGAskRequest(BaseModel):
    question: str
    k: int = 4

class PacketOut(BaseModel):
    id: int
    ts: datetime
    iface: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    bssid: Optional[str] = None
    frame_len: Optional[int] = None
    channel_freq: Optional[int] = None
    datarate: Optional[float] = None
    signal_dbm: Optional[float] = None
    wlan_ds: Optional[int] = None
    wlan_retry: Optional[int] = None
    wlan_type: Optional[int] = None
    wlan_subtype: Optional[int] = None
    wlan_duration: Optional[int] = None
    proba_anomaly: Optional[float] = None
    proba_attack: Optional[float] = None
    predicted_label: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None
    class Config: orm_mode = True

class DetectorConfig(BaseModel):
    iface: str = Field(..., description="monitor interface, e.g., wlan0 or wlan1mon")
    channel: Optional[int] = Field(None, description="Wi-Fi channel (optional)")
    ssid: Optional[str] = None  # For WPA decryption
    wpa_pass: Optional[str] = None  # For WPA decryption
    target_ssid: Optional[str] = Field(None, description="Filter packets to this SSID only")
    target_bssid: Optional[str] = Field(None, description="Filter packets to this BSSID only")
    proba_threshold: float = Field(0.5, ge=0.0, le=1.0)  # raised to be more conservative
    log_all: bool = False

class DetectorStatus(BaseModel):
    running: bool
    seen: int
    saved: int
    attacks: int
    started_at: Optional[str] = None
    message: Optional[str] = None
