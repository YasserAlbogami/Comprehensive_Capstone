#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Standalone 2‑stage Wi‑Fi attack detector (Scapy edition)
- Capture with Scapy (no tshark/pyshark runtime dependency)
- Optional SSID soft filter
- Stage‑1: binary (anomaly) → threshold
- Stage‑2: multiclass (attack type) → threshold
- Only ATTACKS are saved to PostgreSQL (schema given by you)

Run (root):
  sudo -E python3 detector_scapy.py --iface wlan1 --ssid HawkShield --channel 6

Hardcoded (as requested):
  ARTIFACTS_DIR  = "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts"
  DB_URL         = "postgresql+psycopg2://postgres:123456@localhost:5432/projects"
  STAGE1_THRESHOLD = 0.40
  STAGE2_ACCEPT_THRESHOLD = 0.80

Dependencies:
  pip install scapy pandas joblib SQLAlchemy psycopg2-binary
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from joblib import load as joblib_load
from sqlalchemy import JSON, Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# ──────────────────────────────────────────────────────────────────────────────
# Hardcoded constants
# ──────────────────────────────────────────────────────────────────────────────
ARTIFACTS_DIR = "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts"
STAGE1_PATH = os.path.join(ARTIFACTS_DIR, "stage_1", "binary_classifier_final.joblib")
STAGE2_PATH = os.path.join(ARTIFACTS_DIR, "stage_2", "multiclass_lightgbm_bundle.joblib")

# Local fallbacks (from your uploads) if the hardcoded ones are missing
FALLBACK_STAGE1 = "/mnt/data/binary_classifier_final.joblib"
FALLBACK_STAGE2 = "/mnt/data/multiclass_lightgbm_bundle.joblib"

DB_URL = "postgresql+psycopg2://postgres:123456@localhost:5432/projects"

STAGE1_THRESHOLD = 0.40
STAGE2_ACCEPT_THRESHOLD = 0.80

HEARTBEAT_SECS = 2.0

# ──────────────────────────────────────────────────────────────────────────────
# DB model (your schema)
# ──────────────────────────────────────────────────────────────────────────────
Base = declarative_base()

class Packet(Base):
    __tablename__ = "packets"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime, index=True)

    iface = Column(String(64), index=True, nullable=True)
    src_mac = Column(String(32), nullable=True)
    dst_mac = Column(String(32), nullable=True)
    bssid = Column(String(32), nullable=True)

    frame_len = Column(Integer, nullable=True)
    channel_freq = Column(Integer, nullable=True)
    datarate = Column(Float, nullable=True)
    signal_dbm = Column(Float, nullable=True)
    wlan_ds = Column(Integer, nullable=True)
    wlan_retry = Column(Integer, nullable=True)
    wlan_type = Column(Integer, nullable=True)
    wlan_subtype = Column(Integer, nullable=True)
    wlan_duration = Column(Integer, nullable=True)

    proba_anomaly = Column(Float, nullable=True)
    proba_attack = Column(Float, nullable=True)
    predicted_label = Column(String(64), nullable=True)

    raw = Column(JSON, nullable=True)

# ──────────────────────────────────────────────────────────────────────────────
# Scapy import (late, so errors are clearer)
# ──────────────────────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        Dot11,
        Dot11Elt,
        RadioTap,
        sniff,
        conf,
    )
except Exception:
    print("[FATAL] scapy is required. pip install scapy", file=sys.stderr)
    raise

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _to_int(v: Any) -> Optional[int]:
    try:
        if v is None or v == "":
            return None
        return int(float(v))
    except Exception:
        return None


def _to_float(v: Any) -> Optional[float]:
    try:
        if v is None or v == "":
            return None
        return float(v)
    except Exception:
        return None


def _iface_type(iface: str) -> str:
    try:
        out = subprocess.check_output(["iw", "dev", iface, "info"], stderr=subprocess.STDOUT, text=True)
        for ln in out.splitlines():
            ln = ln.strip().lower()
            if ln.startswith("type "):
                return ln.split()[1]
    except Exception:
        pass
    return "unknown"


def _pin_channel(iface: str, channel: int) -> None:
    # best effort
    try:
        subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return
    except Exception:
        pass
    try:
        subprocess.run(["iwconfig", iface, "channel", str(channel)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        print(f"[!] Could not pin {iface} to channel {channel}: {e}")


def _bring_iface_up(iface: str) -> None:
    try:
        subprocess.run(["ip", "link", "set", iface, "up"], check=True)
    except Exception as e:
        print(f"[!] ip link set {iface} up failed: {e}")
    time.sleep(0.3)

# ──────────────────────────────────────────────────────────────────────────────
# Stage wrappers
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Stage1:
    model: Any
    imputer: Any
    scaler: Any
    feature_order: List[str]            # model feature order (what the Booster expects)
    best_threshold: float
    imputer_features: List[str]         # what imputer/scaler expect

    @classmethod
    def from_bundle(cls, path: str) -> "Stage1":
        if not os.path.isfile(path) and os.path.isfile(FALLBACK_STAGE1):
            path = FALLBACK_STAGE1
        b = joblib_load(path)

        model   = b["model"]
        imputer = b.get("imputer") or b.get("num_imputer")
        scaler  = b.get("scaler")

        # Model feature order (can come from bundle or Booster)
        # Model feature order (can come from bundle or Booster)
        feat_model = []
        # 1) from bundle
        fm = b.get("feature_order") or b.get("features")
        if fm:
            feat_model = list(fm)
        # 2) from LightGBM booster
        elif getattr(model, "feature_name", None):
            try:
                feat_model = list(model.feature_name())
            except Exception:
                feat_model = []
        # 3) final fallback
        feat_model = list(feat_model or [])

        # Imputer feature order (often fewer than model’s). DO NOT put numpy arrays in `or` chains.
        imp_attr = getattr(imputer, "feature_names_in_", None)
        if imp_attr is not None:
            try:
                # could be numpy array, pandas Index, or list — normalize to list[str]
                feat_imp = [str(x) for x in list(imp_attr)]
            except Exception:
                feat_imp = []
        else:
            feat_imp = []

        if not feat_imp:
            # fallbacks from bundle, then model features
            feat_imp = list(
                b.get("imputer_features")
                or b.get("imputer_feature_order")
                or feat_model
            )

        thr = float(b.get("best_threshold", STAGE1_THRESHOLD))

        print(
            f"[i] Stage-1 loaded: {path} sha256={_sha256_file(path)} "
            f"n_features_model={len(feat_model)} n_features_imputer={len(feat_imp)}"
        )

        return cls(
            model=model,
            imputer=imputer,
            scaler=scaler,
            feature_order=list(feat_model),
            best_threshold=thr,
            imputer_features=list(feat_imp),
        )

    def _build_df_for(self, cols: List[str], row: Dict[str, Any]) -> pd.DataFrame:
        X = pd.DataFrame([{k: row.get(k, None) for k in cols}], columns=cols)
        for c in X.columns:
            if X[c].dtype == object:
                X[c] = pd.to_numeric(X[c], errors="coerce")
        return X

    def _transform_to_imputer_space(self, row: Dict[str, Any]) -> Optional[pd.DataFrame]:
        X = self._build_df_for(self.imputer_features, row)
        try:
            Xi = self.imputer.transform(X)
        except Exception as e:
            print(f"[err][stage1] imputer.transform failed: {e}")
            return None
        try:
            Xs = self.scaler.transform(Xi)
        except Exception as e:
            print(f"[err][stage1] scaler.transform failed: {e}")
            return None
        return pd.DataFrame(Xs, columns=self.imputer_features)

    def _align_to_model_space(self, X_imp: pd.DataFrame) -> pd.DataFrame:
        if not self.feature_order:
            return X_imp
        out = pd.DataFrame(0.0, index=X_imp.index, columns=self.feature_order)
        inter = [c for c in self.feature_order if c in X_imp.columns]
        if inter:
            out[inter] = X_imp[inter]
        return out

    def _prepare_X(self, row: Dict[str, Any]) -> Optional[pd.DataFrame]:
        X_imp = self._transform_to_imputer_space(row)
        if X_imp is None:
            return None
        return self._align_to_model_space(X_imp)

    def predict_proba(self, row: Dict[str, Any]) -> Optional[float]:
        X = self._prepare_X(row)
        if X is None:
            return None
        m = self.model
        # sklearn style
        if hasattr(m, "predict_proba"):
            try:
                return float(m.predict_proba(X)[0][1])
            except Exception as e:
                print(f"[err][stage1] model.predict_proba failed: {e}")
                return None
        # LightGBM Booster
        if m.__class__.__name__ == "Booster":
            try:
                y = m.predict(
                    X.values,
                    num_iteration=getattr(m, "best_iteration", None),
                    raw_score=False,
                )
                import numpy as np
                return float(np.ravel(y)[0])
            except Exception as e:
                print(f"[err][stage1] booster.predict failed: {e}")
                return None
        # Fallback
        try:
            import numpy as np
            logit = float(m.predict(X)[0])
            return 1.0 / (1.0 + np.exp(-logit))
        except Exception as e:
            print(f"[err][stage1] generic predict failed: {e}")
            return None
    
    def _transform_to_imputer_space(self, row: Dict[str, Any]) -> Optional[pd.DataFrame]:
        # 1) Build DF with exactly the columns the imputer expects
        X = self._build_df_for(self.imputer_features, row)

        # 2) Impute -> wrap back to DataFrame with names
        try:
            Xi = self.imputer.transform(X)
        except Exception as e:
            print(f"[err][{self.__class__.__name__.lower()}] imputer.transform failed: {e}")
            return None
        if not isinstance(Xi, pd.DataFrame):
            Xi = pd.DataFrame(Xi, columns=self.imputer_features)

        # 3) Scale -> again keep as DataFrame with the SAME column names
        try:
            Xs = self.scaler.transform(Xi)
        except Exception as e:
            print(f"[err][{self.__class__.__name__.lower()}] scaler.transform failed: {e}")
            return None
        if not isinstance(Xs, pd.DataFrame):
            Xs = pd.DataFrame(Xs, columns=self.imputer_features)

        return Xs




# ──────────────────────────────────────────────────────────────────────────────
# Stage-2  (single, correct implementation)
# ──────────────────────────────────────────────────────────────────────────────
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

@dataclass
class Stage2:
    model: Any
    imputer: Any
    scaler: Any
    feature_order: List[str]            # model feature order (what the classifier expects)
    id_to_class: Dict[int, str]
    imputer_features: List[str]         # what the imputer/scaler were fit on

    @classmethod
    def from_bundle(cls, path: str) -> "Stage2":
        # Allow your fallback path if needed
        if not os.path.isfile(path) and os.path.isfile(FALLBACK_STAGE2):
            path = FALLBACK_STAGE2
        b = joblib_load(path)

        model   = b["model"]
        imputer = b["num_imputer"]
        scaler  = b["scaler"]

        # Model feature order
        model_feats = list(b.get("feature_order", []))
        if not model_feats and getattr(model, "feature_name", None):
            try:
                model_feats = list(model.feature_name())
            except Exception:
                model_feats = []

        # What the imputer expects (prefer its own recorded names)
        imp_feats = list(getattr(imputer, "feature_names_in_", model_feats)) or list(model_feats)

        id_to_class = b.get("id_to_class", {})
        print(
            f"[i] Stage-2 loaded: {path} sha256={_sha256_file(path)} "
            f"n_features_model={len(model_feats)} n_features_imputer={len(imp_feats)} "
            f"n_classes={len(id_to_class) or 'unknown'}"
        )
        return cls(
            model=model,
            imputer=imputer,
            scaler=scaler,
            feature_order=list(model_feats),
            id_to_class=id_to_class,
            imputer_features=list(imp_feats),
        )

    # ----- internals ----------------------------------------------------------

    def _build_df_for(self, cols: List[str], row: Dict[str, Any]) -> pd.DataFrame:
        X = pd.DataFrame([{k: row.get(k, None) for k in cols}], columns=cols)
        for c in X.columns:
            if X[c].dtype == object:
                X[c] = pd.to_numeric(X[c], errors="coerce")
        return X

    def _transform_to_imputer_space(self, row: Dict[str, Any]) -> Optional[pd.DataFrame]:
        """
        Keep pandas DataFrame all the way into scaler.transform to avoid:
        'X does not have valid feature names, but StandardScaler was fitted with feature names'
        """
        # 1) exact columns the imputer was fit on
        X = self._build_df_for(self.imputer_features, row)

        # 2) impute -> wrap back to DataFrame with SAME column names
        try:
            Xi = self.imputer.transform(X)
        except Exception as e:
            print(f"[err][stage2] imputer.transform failed: {e}")
            return None
        if not isinstance(Xi, pd.DataFrame):
            Xi = pd.DataFrame(Xi, columns=self.imputer_features)

        # 3) scale -> again keep DataFrame (names preserved)
        try:
            Xs = self.scaler.transform(Xi)
        except Exception as e:
            print(f"[err][stage2] scaler.transform failed: {e}")
            return None
        if not isinstance(Xs, pd.DataFrame):
            Xs = pd.DataFrame(Xs, columns=self.imputer_features)

        return Xs

    def _align_to_model_space(self, X_imp: pd.DataFrame) -> pd.DataFrame:
        """Align to model feature order; fill missing with 0.0."""
        if not self.feature_order:
            return X_imp
        out = pd.DataFrame(0.0, index=X_imp.index, columns=self.feature_order, dtype=float)
        inter = [c for c in self.feature_order if c in X_imp.columns]
        if inter:
            out[inter] = X_imp[inter]
        return out

    def _prepare_X(self, row: Dict[str, Any]) -> Optional[pd.DataFrame]:
        X_imp = self._transform_to_imputer_space(row)
        if X_imp is None:
            return None
        return self._align_to_model_space(X_imp)

    # ----- inference ----------------------------------------------------------

    def predict(self, row: Dict[str, Any]) -> Tuple[Optional[str], Optional[float]]:
        """Return (label, confidence). Supports sklearn estimators and LightGBM Booster."""
        X = self._prepare_X(row)
        if X is None:
            return None, None

        m = self.model

        # 1) sklearn-style estimators
        if hasattr(m, "predict_proba"):
            try:
                import numpy as np
                probs = m.predict_proba(X)[0]
                cls_id = int(np.argmax(probs))
                return self.id_to_class.get(cls_id, str(cls_id)), float(probs[cls_id])
            except Exception as e:
                print(f"[err][stage2] predict_proba failed: {e}")
                return None, None

        # 2) LightGBM Booster
        if m.__class__.__name__ == "Booster":
            try:
                import numpy as np
                y = m.predict(
                    X.values,
                    num_iteration=getattr(m, "best_iteration", None),
                    raw_score=False,
                )
                y = np.asarray(y)

                # Shapes to handle:
                #  - multiclass, single row: (num_class,)
                #  - multiclass, single row as 2D: (1, num_class)
                #  - binary, single row: scalar or (1,) -> convert to [1-p, p]
                if y.ndim == 0:
                    p1 = float(y)
                    probs = np.array([1.0 - p1, p1], dtype=float)
                elif y.ndim == 1:
                    if getattr(m, "num_class", 1) > 2:
                        probs = y
                    else:
                        p1 = float(y[0])
                        probs = np.array([1.0 - p1, p1], dtype=float)
                else:
                    probs = y[0]

                cls_id = int(np.argmax(probs))
                return self.id_to_class.get(cls_id, str(cls_id)), float(probs[cls_id])
            except Exception as e:
                print(f"[err][stage2] booster.predict failed: {e}")
                return None, None

        # 3) Fallback: hard label only
        try:
            pred = int(m.predict(X)[0])
            return self.id_to_class.get(pred, str(pred)), 1.0
        except Exception as e:
            print(f"[err][stage2] generic predict failed: {e}")
            return None, None


# ──────────────────────────────────────────────────────────────────────────────
# Feature extraction from Scapy pkt → row (names match training set)
# ──────────────────────────────────────────────────────────────────────────────

EXPECTED_KEYS_HINT = [
    # A superset; real used set will be taken from imputer.feature_names_in_
    "frame.encap_type",
    "frame.len",
    "frame.time_delta",
    "frame.time_delta_displayed",
    "frame.time_relative",
    "radiotap.channel.flags.cck",
    "radiotap.channel.flags.ofdm",
    "radiotap.channel.freq",
    "radiotap.datarate",
    "radiotap.dbm_antsignal",
    "radiotap.length",
    "radiotap.rxflags",
    "wlan.duration",
    "wlan.fc.ds",
    "wlan.fc.frag",
    "wlan.fc.order",
    "wlan.fc.moredata",
    "wlan.fc.protected",
    "wlan.fc.pwrmgt",
    "wlan.fc.type",
    "wlan.fc.retry",
    "wlan.fc.subtype",
    "wlan_radio.duration",
    "wlan.seq",
    "wlan_radio.channel",
    "wlan_radio.data_rate",
    "wlan_radio.frequency",
    "wlan_radio.signal_dbm",
    "wlan_radio.phy",
]


def _dot11_addrs(pkt: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    sa = getattr(pkt, "addr2", None)
    da = getattr(pkt, "addr1", None)
    bssid = getattr(pkt, "addr3", None)
    return sa, da, bssid


def _ssid_from_beacon_or_probe(pkt: Any) -> Optional[str]:
    try:
        if pkt.haslayer(Dot11Elt):
            elts = pkt.getlayer(Dot11Elt)
            while isinstance(elts, Dot11Elt):
                if getattr(elts, "ID", None) == 0:  # SSID parameter set
                    ssid = bytes(getattr(elts, "info", b""))
                    try:
                        return ssid.decode(errors="ignore")
                    except Exception:
                        return None
                elts = elts.payload if hasattr(elts, "payload") else None
    except Exception:
        pass
    return None


def scapy_to_row(pkt: Any, iface: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Return (row_for_model, raw_for_db_minimal)."""
    row: Dict[str, Any] = {}

    # Radiotap fields (best effort; not all drivers expose all of these)
    rt = pkt.getlayer(RadioTap)
    row["radiotap.datarate"] = _to_float(getattr(rt, "Rate", None))
    row["radiotap.dbm_antsignal"] = _to_float(getattr(rt, "dBm_AntSignal", None))
    row["radiotap.length"] = _to_float(getattr(rt, "len", None))
    # channel info might not be available from scapy in all drivers; best effort
    row["radiotap.channel.freq"] = None
    row["radiotap.channel.flags.cck"] = None
    row["radiotap.channel.flags.ofdm"] = None

    # Frame fields
    d11 = pkt.getlayer(Dot11)
    row["frame.len"] = _to_int(len(pkt)) if pkt is not None else None
    row["wlan.fc.type"] = _to_int(getattr(d11, "type", None))
    row["wlan.fc.subtype"] = _to_int(getattr(d11, "subtype", None))
    row["wlan.fc.retry"] = 1 if getattr(d11, "FCfield", 0) & 0x08 else 0
    row["wlan.fc.ds"] = 0  # not exposed cleanly via scapy; fill with 0
    row["wlan.fc.moredata"] = 1 if getattr(d11, "FCfield", 0) & 0x20 else 0
    row["wlan.fc.protected"] = 1 if getattr(d11, "FCfield", 0) & 0x40 else 0
    row["wlan.fc.pwrmgt"] = 1 if getattr(d11, "FCfield", 0) & 0x10 else 0
    row["wlan.fc.frag"] = None
    row["wlan.fc.order"] = None
    row["wlan.duration"] = _to_int(getattr(d11, "ID", None) if hasattr(d11, "ID") else None)

    # Time‑related placeholders (scapy live doesn’t compute Wireshark deltas)
    row["frame.encap_type"] = None
    row["frame.time_delta"] = None
    row["frame.time_delta_displayed"] = None
    row["frame.time_relative"] = None

    # Wireshark "wlan_radio.*" placeholders (scapy names differ) – best effort
    row["wlan_radio.data_rate"] = row["radiotap.datarate"]
    row["wlan_radio.signal_dbm"] = row["radiotap.dbm_antsignal"]
    row["wlan_radio.frequency"] = row["radiotap.channel.freq"]
    row["wlan_radio.channel"] = None
    row["wlan_radio.duration"] = None
    row["wlan_radio.phy"] = None

    # Addresses
    sa, da, bssid = _dot11_addrs(d11) if d11 else (None, None, None)

    # Soft SSID capture (for UI debug and soft filter)
    ssid = _ssid_from_beacon_or_probe(pkt)

    raw_min = {
        "iface": iface,
        "sa": sa,
        "da": da,
        "bssid": bssid,
        "len": row["frame.len"],
        "type": row["wlan.fc.type"],
        "subtype": row["wlan.fc.subtype"],
        "rate": row["radiotap.datarate"],
        "sig": row["radiotap.dbm_antsignal"],
        "ssid": ssid,
    }

    # Add extras often used in DB
    row["wlan.seq"] = None

    return row, raw_min

# ──────────────────────────────────────────────────────────────────────────────
# Detector
# ──────────────────────────────────────────────────────────────────────────────

class Detector:
    def __init__(self, iface: str, channel: int, ssid: Optional[str]):
        self.iface = iface
        self.channel = int(channel)
        self.ssid = (ssid or "").strip() or None

        self.engine = create_engine(DB_URL, pool_pre_ping=True)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

        self.stage1 = Stage1.from_bundle(STAGE1_PATH)
        self.stage2 = Stage2.from_bundle(STAGE2_PATH)

        self.seen = 0
        self.saved = 0
        self.stop_flag = threading.Event()
        self.last_hb = time.time()

    # ────────────── persistence ──────────────
    def _save_attack(self, raw: Dict[str, Any], row: Dict[str, Any], p1: float, p2: float, label: str):
        ts = _now_utc()
        sa = raw.get("sa")
        da = raw.get("da")
        bssid = raw.get("bssid")

        rec = Packet(
            ts=ts,
            iface=self.iface,
            src_mac=sa,
            dst_mac=da,
            bssid=bssid,
            frame_len=row.get("frame.len"),
            channel_freq=row.get("radiotap.channel.freq"),
            datarate=row.get("radiotap.datarate"),
            signal_dbm=row.get("radiotap.dbm_antsignal"),
            wlan_ds=row.get("wlan.fc.ds"),
            wlan_retry=row.get("wlan.fc.retry"),
            wlan_type=row.get("wlan.fc.type"),
            wlan_subtype=row.get("wlan.fc.subtype"),
            wlan_duration=row.get("wlan.duration"),
            proba_anomaly=p1,
            proba_attack=p2,
            predicted_label=label,
            raw=raw,
        )
        try:
            with self.Session() as s:
                s.add(rec)
                s.commit()
                self.saved += 1
        except Exception as e:
            print(f"[err][db] commit failed: {e}")

    # ────────────── packet handler ──────────────
    def _on_packet(self, pkt: Any):
        self.seen += 1
        try:
            row, raw = scapy_to_row(pkt, self.iface)
            # Soft SSID filter
            if self.ssid:
                pkt_ssid = raw.get("ssid")
                if pkt_ssid is not None and pkt_ssid != self.ssid:
                    return

            # Stage‑1
            p1 = self.stage1.predict_proba(row)
            print(p1)
            if p1 is None or p1 < STAGE1_THRESHOLD:
                return

            # Stage‑2
            label, p2 = self.stage2.predict(row)
            print(f"label={label} with {p2} confidence")
            if label is None or p2 is None or p2 < STAGE2_ACCEPT_THRESHOLD:
                return

            # Persist only ATTACKS
            self._save_attack(raw=raw, row=row, p1=p1, p2=p2, label=label)
        except Exception as e:
            print(f"[err] _on_packet: {e}")

    # ────────────── heartbeat ──────────────
    def _heartbeat(self):
        while not self.stop_flag.is_set():
            now = time.time()
            if now - self.last_hb >= HEARTBEAT_SECS:
                self.last_hb = now
                print(f"[hb] status=LIVE seen={self.seen} saved={self.saved} iface={self.iface} ch={self.channel}")
            time.sleep(0.2)

    # ────────────── run/stop ──────────────
    def run(self):
        # Try to ensure monitor + channel pin
        itype = _iface_type(self.iface)
        ask_monitor = False
        if itype != "monitor":
            ask_monitor = True
            try:
                subprocess.run(["ip", "link", "set", self.iface, "down"], check=True)
                subprocess.run(["iw", self.iface, "set", "monitor", "none"], check=True)
                subprocess.run(["ip", "link", "set", self.iface, "up"], check=True)
                itype = _iface_type(self.iface)
            except Exception as e:
                print(f"[!] Could not switch {self.iface} to monitor: {e}")
        _pin_channel(self.iface, self.channel)
        _bring_iface_up(self.iface)

        try:
            conf.sniff_promisc = True
            conf.monitor = 1
        except Exception:
            pass

        print(f"[i] Iface={self.iface} type={itype} ask_monitor={ask_monitor} filter={'ON' if self.ssid else 'OFF'}")
        print(f"[i] Scapy sniffer armed: iface={self.iface} type={_iface_type(self.iface)} channel={self.channel} ssid='{self.ssid or ''}' thr1={STAGE1_THRESHOLD} thr2={STAGE2_ACCEPT_THRESHOLD}")

        hb = threading.Thread(target=self._heartbeat, daemon=True)
        hb.start()

        while not self.stop_flag.is_set():
            try:
                sniff(
                    iface=self.iface,
                    prn=self._on_packet,
                    store=False,
                    timeout=10,
                    stop_filter=lambda _: self.stop_flag.is_set(),
                )
            except OSError as e:
                if getattr(e, "errno", None) == errno.ENETDOWN or "Network is down" in str(e):
                    print("[!] Sniffer says network is down; bringing interface up and retrying…")
                    _bring_iface_up(self.iface)
                    _pin_channel(self.iface, self.channel)
                    continue
                else:
                    print(f"[!] Sniffer OSError: {e}")
                    time.sleep(1)
                    continue
            except KeyboardInterrupt:
                print("[i] Ctrl-C; stopping…")
                self.stop_flag.set()
                break
            except Exception as e:
                print(f"[!] Sniffer error: {e}")
                time.sleep(1)
                continue

    def stop(self):
        self.stop_flag.set()

# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="2‑stage Wi‑Fi attack detector (Scapy)")
    ap.add_argument("--iface", required=True, help="wlan interface in monitor mode (e.g., wlan1)")
    ap.add_argument("--channel", type=int, default=6, help="channel to pin")
    ap.add_argument("--ssid", default=None, help="optional SSID to soft‑filter")
    args = ap.parse_args()

    det = Detector(iface=args.iface, channel=args.channel, ssid=args.ssid)

    def _sigterm(*_):
        det.stop()
    signal.signal(signal.SIGTERM, _sigterm)

    det.run()

if __name__ == "__main__":
    main()
