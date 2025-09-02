# detector.py
# Two-stage live detector:
#   Stage-1 (binary): attack vs normal
#   Stage-2 (multiclass): if attack, classify the attack type (Deauth, Krack, etc.)
#
# Uses pyshark to stream fields, shapes them to the feature list, runs preprocessor(s) or a bundled Pipeline,
# and saves rows (attacks or all if log_all=True) into the DB.
#
# NOTE (2025-08-28): Updated to:
#  - Load Stage-1 model from /mnt/data/binary_ids_lightgbm_bundle.joblib (can be overridden via STAGE1_CLF_PATH)
#  - Use the exact 31-feature list provided by the user for Stage-1 (and Stage-2 by default)
#  - BYPASS apply_intelligent_override (no rule-based probability override; proba = model output)
#  - If Stage-1 classifier is a sklearn Pipeline (with preprocessing), we pass the raw DataFrame (no float casting)

import os, json, time, signal, threading
from datetime import datetime
from typing import Optional, Dict, Any, List

import numpy as np
import pandas as pd

from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import pyshark
from dotenv import load_dotenv

from db import SessionLocal, Packet
from schemas import DetectorConfig, DetectorStatus

try:
    import joblib
except Exception:
    joblib = None

load_dotenv()

# =========================
# Utilities
# =========================

def send_deauth(src_mac, bssid, iface):
    """Send a deauth frame to the attacker using Scapy."""
    if not src_mac or not bssid or not iface:
        print(f"[!] Missing MAC/BSSID/iface for deauth: src_mac={src_mac}, bssid={bssid}, iface={iface}")
        return
    pkt = RadioTap()/Dot11(addr1=src_mac, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
    try:
        sendp(pkt, iface=iface, count=5, inter=0.1, verbose=False)
        print(f"[✓] Sent deauth to {src_mac} on {iface}")
    except Exception as e:
        print(f"[!] Failed to send deauth: {e}")

def _unique(seq):
    s = set(); out=[]
    for x in seq:
        if x not in s:
            s.add(x); out.append(x)
    return out

# =========================
# Paths and configuration
# =========================

# ---- Stage-1 (binary) artifacts ----
# Default to the uploaded bundle (can be a Pipeline with preprocessing inside)
STAGE1_CLF_PATH = os.environ.get(
    "STAGE1_CLF_PATH",
    "/mnt/data/binary_ids_lightgbm_bundle.joblib"
)
# If you ALSO have a separate preprocessor, set these env vars; otherwise they can be missing.
STAGE1_PREPROC_PATH = os.environ.get("STAGE1_PREPROCESSOR_PATH", "/root/Desktop/Capstone1/artifacts/stage_1/preprocessor.joblib")
STAGE1_FEATURES_PATH = os.environ.get("STAGE1_FEATURES_PATH")  # optional JSON list

# ---- Stage-2 (multiclass) artifacts (optional) ----
STAGE2_CLF_PATH = os.environ.get("STAGE2_CLF_PATH")
STAGE2_PREPROC_PATH = os.environ.get("STAGE2_PREPROCESSOR_PATH")      # optional
STAGE2_FEATURES_PATH = os.environ.get("STAGE2_FEATURES_PATH")         # optional (JSON list)

# Optional anomaly model (not required)
ANOMALY_MODEL_PATH = os.environ.get("ANOMALY_MODEL_PATH")

# -------- Feature List (Provided by user) --------
# Exact 31 features to match the new Stage-1 model:
USER_STAGE1_FEATURES = [
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
    "wlan.country_info.fnm",
    "wlan.country_info.code",
]

def _load_feature_list(path: Optional[str], fallback: List[str]) -> List[str]:
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and all(isinstance(x, str) for x in data):
                print(f"[i] Loaded features from JSON: {path} (n={len(data)})")
                return data
            else:
                print(f"[i] Feature JSON is not a simple list of strings: {path}")
        except Exception as e:
            print(f"[i] Could not load features from {path}: {e}")
    return fallback

# Use user-provided 31 features by default; allow JSON override if explicitly provided
FEATURES_STAGE1 = _load_feature_list(STAGE1_FEATURES_PATH, USER_STAGE1_FEATURES)
# Stage-2 features default to Stage-1 unless provided:
FEATURES_STAGE2 = _load_feature_list(STAGE2_FEATURES_PATH, FEATURES_STAGE1)

# Always capture these extra fields for metadata/time
EXTRA_FIELDS = ["wlan.sa", "wlan.da", "wlan.bssid", "frame.time_epoch"]

# Build tshark fields (de-dup preserving order) = union(Stage1, Stage2, EXTRA)
TSHARK_FIELDS = _unique(FEATURES_STAGE1 + FEATURES_STAGE2 + EXTRA_FIELDS)

# Mapping between radiotap and wlan_radio naming (best-effort)
MIRRORS = {
    "wlan_radio.data_rate": "radiotap.datarate",
    "wlan_radio.signal_dbm": "radiotap.dbm_antsignal",
    "wlan_radio.frequency": "radiotap.channel.freq",
    "wlan_radio.channel": "radiotap.channel.freq",  # approximate (use freq as proxy)
    "wlan_radio.duration": "wlan.duration",
}

# Which fields should be treated as binary flags
FLAG_LIKE = set([
    "radiotap.channel.flags.cck", "radiotap.channel.flags.ofdm",
    "wlan.fc.ds","wlan.fc.frag","wlan.fc.order","wlan.fc.moredata",
    "wlan.fc.protected","wlan.fc.pwrmgt","wlan.fc.retry"
])

def _parse_flag(v):
    if v is None or v == "":
        return 0
    v = str(v).strip().lower()
    return 1 if v in ("1","true","yes","y","t","on") else 0

def _parse_numeric(v):
    if v is None or v == "" or v == "-":
        return np.nan
    s = str(v).strip()
    if s.lower().startswith("0x"):
        try:
            return float(int(s[2:], 16))
        except: 
            return np.nan
    if s.lower() in ("true","false","yes","no","on","off"):
        return float(_parse_flag(s))
    try:
        return float(s)
    except:
        return np.nan

def _parse_pyshark_packet(packet) -> Optional[Dict[str, Any]]:
    """Parse a pyshark packet into our feature dictionary."""
    try:
        row: Dict[str, Any] = {}
        
        # frame
        if hasattr(packet, 'frame_info'):
            frame = packet.frame_info
            row["frame.encap_type"] = _parse_numeric(getattr(frame, 'encap_type', None))
            row["frame.len"] = _parse_numeric(getattr(frame, 'len', None))
            row["frame.time_delta"] = _parse_numeric(getattr(frame, 'time_delta', None))
            row["frame.time_delta_displayed"] = _parse_numeric(getattr(frame, 'time_delta_displayed', None))
            row["frame.time_relative"] = _parse_numeric(getattr(frame, 'time_relative', None))
            row["frame.time_epoch"] = _parse_numeric(getattr(frame, 'time_epoch', None))
        
        # radiotap
        if hasattr(packet, 'radiotap'):
            rt = packet.radiotap
            row["radiotap.channel.freq"] = _parse_numeric(getattr(rt, 'channel_freq', None))
            row["radiotap.datarate"] = _parse_numeric(getattr(rt, 'datarate', None))
            row["radiotap.dbm_antsignal"] = _parse_numeric(getattr(rt, 'dbm_antsignal', None))
            row["radiotap.length"] = _parse_numeric(getattr(rt, 'length', None))
            row["radiotap.rxflags"] = _parse_numeric(getattr(rt, 'rxflags', None))
            row["radiotap.channel.flags.cck"] = _parse_flag(getattr(rt, 'channel_flags_cck', None))
            row["radiotap.channel.flags.ofdm"] = _parse_flag(getattr(rt, 'channel_flags_ofdm', None))
        
        # wlan
        if hasattr(packet, 'wlan'):
            wlan = packet.wlan
            row["wlan.duration"] = _parse_numeric(getattr(wlan, 'duration', None))
            row["wlan.seq"] = _parse_numeric(getattr(wlan, 'seq', None))

            # MACs
            row["wlan.sa"] = (getattr(wlan, 'sa', None) or getattr(wlan, 'addr2', None) or getattr(wlan, 'ta', None))
            row["wlan.da"] = (getattr(wlan, 'da', None) or getattr(wlan, 'addr1', None) or getattr(wlan, 'ra', None))
            row["wlan.bssid"] = (getattr(wlan, 'bssid', None) or getattr(wlan, 'addr3', None))

            # FC fields
            row["wlan.fc.ds"] = _parse_flag(getattr(wlan, 'fc_ds', None))
            row["wlan.fc.frag"] = _parse_flag(getattr(wlan, 'fc_frag', None))
            row["wlan.fc.order"] = _parse_flag(getattr(wlan, 'fc_order', None))
            row["wlan.fc.moredata"] = _parse_flag(getattr(wlan, 'fc_moredata', None))
            row["wlan.fc.protected"] = _parse_flag(getattr(wlan, 'fc_protected', None))
            row["wlan.fc.pwrmgt"] = _parse_flag(getattr(wlan, 'fc_pwrmgt', None))
            row["wlan.fc.type"] = _parse_numeric(getattr(wlan, 'fc_type', None))
            row["wlan.fc.retry"] = _parse_flag(getattr(wlan, 'fc_retry', None))
            row["wlan.fc.subtype"] = _parse_numeric(getattr(wlan, 'fc_subtype', None))

            # Country info
            row["wlan.country_info.fnm"] = _parse_numeric(getattr(wlan, 'country_info_fnm', None))
            # Keep code as string; Pipeline (if present) can encode it
            row["wlan.country_info.code"] = getattr(wlan, 'country_info_code', None)

        # wlan_radio (alternative to radiotap)
        if hasattr(packet, 'wlan_radio'):
            wr = packet.wlan_radio
            row["wlan_radio.duration"] = _parse_numeric(getattr(wr, 'duration', None))
            row["wlan_radio.channel"] = _parse_numeric(getattr(wr, 'channel', None))
            row["wlan_radio.data_rate"] = _parse_numeric(getattr(wr, 'data_rate', None))
            row["wlan_radio.frequency"] = _parse_numeric(getattr(wr, 'frequency', None))
            row["wlan_radio.signal_dbm"] = _parse_numeric(getattr(wr, 'signal_dbm', None))
            row["wlan_radio.phy"] = _parse_numeric(getattr(wr, 'phy', None))
        
        # processed_row with all expected fields
        processed_row: Dict[str, Any] = {}
        for f in TSHARK_FIELDS:
            processed_row[f] = np.nan

        # Fill values; try mirrors if missing
        for f in TSHARK_FIELDS:
            if f in EXTRA_FIELDS:
                continue
            val = row.get(f)
            if (val in (None, "", "-")) and f in MIRRORS:
                alt = MIRRORS[f]
                val = row.get(alt)
            if val is not None and val != "" and val != "-":
                if f in FLAG_LIKE:
                    processed_row[f] = float(_parse_flag(val))
                else:
                    # IMPORTANT: Do NOT coerce strings to float here; we keep as-is,
                    # numeric features will already be numeric via _parse_numeric,
                    # and string features (like country code) remain strings.
                    processed_row[f] = val

        # meta
        processed_row["src_mac"] = row.get("wlan.sa") or None
        processed_row["dst_mac"] = row.get("wlan.da") or None
        processed_row["bssid"] = row.get("wlan.bssid") or None
        processed_row["time_epoch"] = _parse_numeric(row.get("frame.time_epoch"))
        return processed_row
    except Exception as e:
        print(f"[!] Failed to parse packet: {e}")
        return None

def _create_pyshark_capture(cfg: DetectorConfig):
    """Create a pyshark capture object with appropriate filters."""
    custom_params = []
    if cfg.wpa_pass and cfg.ssid:
        custom_params = [
            '-o', 'wlan.enable_decryption:TRUE',
            '-o', f'uat:80211_keys:"wpa-pwd","{cfg.wpa_pass}","{cfg.ssid}","",""'
        ]

    display_filter = None
    target_ssid = cfg.target_ssid or os.environ.get('TARGET_SSID')
    target_bssid = cfg.target_bssid or os.environ.get('TARGET_BSSID')

    if target_ssid:
        if target_bssid:
            display_filter = (
                f'(wlan.ssid == "{target_ssid}") or '
                f'(wlan.bssid == "{target_bssid}") or '
                f'(wlan.sa == "{target_bssid}") or '
                f'(wlan.da == "{target_bssid}") or '
                f'(wlan.fc.type == 0 and (wlan.addr1 == "{target_bssid}" or wlan.addr2 == "{target_bssid}" or wlan.addr3 == "{target_bssid}"))'
            )
        else:
            display_filter = f'(wlan.ssid == "{target_ssid}") or (wlan.fc.type == 0)'
        print(f"[i] Using enhanced filter for deauth detection: {display_filter}")
        print(f"[i] Filtering for SSID: {target_ssid}" + (f" and BSSID: {target_bssid}" if target_bssid else ""))
    else:
        print(f"[!] No SSID filter set - capturing all networks!")
        print(f"[!] Set TARGET_SSID env var or use target_ssid in config to filter")

    try:
        print(f"[i] Creating pyshark capture on interface: {cfg.iface}")
        capture = pyshark.LiveCapture(
            interface=cfg.iface,
            display_filter=display_filter,
            custom_parameters=custom_params if custom_params else None
        )
        print(f"[i] Pyshark capture created with filter: {display_filter}")
        return capture
    except Exception as e:
        print(f"[!] Failed to create pyshark capture: {e}")
        return None

# =========================
# Detector
# =========================

class Detector:
    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._capture = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._cfg: Optional[DetectorConfig] = None
        self._started_at: Optional[float] = None
        self._seen = 0
        self._saved = 0
        self._attacks = 0

        # Artifacts
        self.stage1_preproc = None
        self.stage1_clf = None
        self.stage2_preproc = None
        self.stage2_clf = None
        self.anomaly_model = None  # optional

        self._load_artifacts()

    # -------- reload support --------
    def reload_artifacts(self):
        self._load_artifacts()

    def _load_artifacts(self):
        global FEATURES_STAGE1, FEATURES_STAGE2, TSHARK_FIELDS

        # Features
        FEATURES_STAGE1 = _load_feature_list(STAGE1_FEATURES_PATH, USER_STAGE1_FEATURES)
        FEATURES_STAGE2 = _load_feature_list(STAGE2_FEATURES_PATH, FEATURES_STAGE1)
        TSHARK_FIELDS = _unique(FEATURES_STAGE1 + FEATURES_STAGE2 + EXTRA_FIELDS)

        print(f"[i] Stage-1 features: {len(FEATURES_STAGE1)} → {FEATURES_STAGE1}")
        if FEATURES_STAGE2 is FEATURES_STAGE1:
            print(f"[i] Stage-2 features: same as Stage-1 (n={len(FEATURES_STAGE2)})")
        else:
            print(f"[i] Stage-2 features: {len(FEATURES_STAGE2)}")

        if joblib is None:
            print("[!] joblib not available.")
            return

        # Stage-1 preprocessor (optional)
        try:
            if STAGE1_PREPROC_PATH and os.path.exists(STAGE1_PREPROC_PATH):
                self.stage1_preproc = joblib.load(STAGE1_PREPROC_PATH)
                print("[✓] Stage-1 preprocessor:", STAGE1_PREPROC_PATH)
            else:
                self.stage1_preproc = None
                if STAGE1_PREPROC_PATH:
                    print("[i] Stage-1 preprocessor not found or not set:", STAGE1_PREPROC_PATH)
        except Exception as e:
            self.stage1_preproc = None
            print(f"[!] Failed to load Stage-1 preprocessor: {e}")

        # Stage-1 classifier (bundle / pipeline or plain model)
        try:
            if STAGE1_CLF_PATH and os.path.exists(STAGE1_CLF_PATH):
                self.stage1_clf = joblib.load(STAGE1_CLF_PATH)
                print("[✓] Stage-1 classifier:", STAGE1_CLF_PATH)
            else:
                print("[!] Stage-1 classifier not found:", STAGE1_CLF_PATH)
        except Exception as e:
            print(f"[!] Failed to load Stage-1 classifier: {e}")

        # Stage-2 (optional)
        try:
            if STAGE2_PREPROC_PATH and os.path.exists(STAGE2_PREPROC_PATH):
                self.stage2_preproc = joblib.load(STAGE2_PREPROC_PATH)
                print("[✓] Stage-2 preprocessor:", STAGE2_PREPROC_PATH)
            else:
                self.stage2_preproc = self.stage1_preproc
                print("[i] Stage-2 preprocessor not set; reusing Stage-1 preprocessor (if any).")
        except Exception as e:
            self.stage2_preproc = self.stage1_preproc
            print(f"[!] Failed to load Stage-2 preprocessor: {e}")

        try:
            if STAGE2_CLF_PATH and os.path.exists(STAGE2_CLF_PATH):
                self.stage2_clf = joblib.load(STAGE2_CLF_PATH)
                print("[✓] Stage-2 classifier:", STAGE2_CLF_PATH)
            else:
                print("[i] Stage-2 classifier not set.")
        except Exception as e:
            print(f"[!] Failed to load Stage-2 classifier: {e}")

        # Optional anomaly
        try:
            if ANOMALY_MODEL_PATH and os.path.exists(ANOMALY_MODEL_PATH):
                self.anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
                print("[✓] Anomaly model:", ANOMALY_MODEL_PATH)
        except Exception as e:
            print(f"[!] Failed to load anomaly model: {e}")

        print("="*50)

    # -------- API status --------
    def status(self) -> DetectorStatus:
        return DetectorStatus(
            running=self._thread is not None and self._thread.is_alive(),
            seen=self._seen, saved=self._saved, attacks=self._attacks,
            started_at=datetime.utcfromtimestamp(self._started_at).isoformat() + "Z" if self._started_at else None,
            message="ok" if self._thread and self._thread.is_alive() else "stopped"
        )

    # -------- lifecycle --------
    def start(self, cfg: DetectorConfig):
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("Detector already running")
            self._cfg = cfg
            self._stop.clear()
            self._seen = 0
            self._saved = 0
            self._attacks = 0
            self._thread = threading.Thread(target=self._run, name="LiveDetector", daemon=True)
            self._thread.start()

    def stop(self):
        with self._lock:
            self._stop.set()
            if self._capture:
                try:
                    self._capture.close()
                except Exception:
                    pass
            self._capture = None

    # -------- DataFrame helpers --------
    def _ensure_columns(self, df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
        """Ensure DataFrame has all required columns, adding missing ones with NaN."""
        missing_cols = []
        for c in cols:
            if c not in df.columns:
                df[c] = np.nan
                missing_cols.append(c)
        if missing_cols:
            print(f"[FEATURE_WARNING] Added {len(missing_cols)} missing columns with NaN: {missing_cols[:10]}{'...' if len(missing_cols) > 10 else ''}")
        # preserve order
        return df[cols]

    def _prepare_input(self, df: pd.DataFrame, features: List[str], preproc, est) -> pd.DataFrame:
        """
        Prepare X for a model:
          - If preproc is provided, caller should use _transform (not here).
          - If est looks like a sklearn Pipeline (has 'steps' or 'named_steps'), return the raw DataFrame
            (pipelines can handle string columns like 'wlan.country_info.code').
          - Else, cast to float32 with NaNs filled (legacy plain models).
        """
        df = self._ensure_columns(df, features)
        if preproc is not None:
            # caller should not use this function if preproc is provided
            return df
        if hasattr(est, "steps") or hasattr(est, "named_steps"):
            return df  # let Pipeline handle preprocessing/encoding
        # fallback: numeric only
        return df.astype("float32").fillna(0)

    def _transform(self, df: pd.DataFrame, features: List[str], preproc) -> pd.DataFrame:
        """Apply a separate preprocessor (if you actually have one saved separately)."""
        df = self._ensure_columns(df, features)
        if preproc is not None:
            try:
                X = preproc.transform(df)
                if isinstance(X, np.ndarray):
                    if hasattr(preproc, 'get_feature_names_out'):
                        try:
                            cols = preproc.get_feature_names_out()
                            return pd.DataFrame(X, columns=cols)
                        except:
                            pass
                    return pd.DataFrame(X, columns=[f'feature_{i}' for i in range(X.shape[1])])
                return X
            except Exception as e:
                print(f"[!] preprocessor.transform failed: {e}")
                return df.astype("float32").fillna(0)
        return df.astype("float32").fillna(0)

    # -------- Estimator helpers --------
    @staticmethod
    def _proba_from_estimator(est, X) -> Optional[float]:
        if est is None: return None
        try:
            input_data = X if isinstance(X, (pd.DataFrame, pd.Series)) else np.asarray(X)
            if hasattr(est, "predict_proba"):
                p = est.predict_proba(input_data)
                if p.ndim == 2 and p.shape[1] >= 2:
                    return float(np.clip(p[0, -1], 0, 1))  # prob(attack)
                return float(np.clip(p[0, 0], 0, 1))
            if hasattr(est, "decision_function"):
                d = est.decision_function(input_data)
                return float(1 / (1 + np.exp(-float(d[0]))))
            if hasattr(est, "predict"):
                y = est.predict(input_data)
                if isinstance(y[0], (int, float, np.floating)): return float(y[0])
        except Exception as e:
            print(f"[!] proba_from_estimator failed: {e}")
        return None

    @staticmethod
    def _detailed_proba_from_estimator(est, X, model_name: str) -> Dict[str, Any]:
        result = {
            'model_name': model_name,
            'available': est is not None,
            'attack_probability': None,
            'all_probabilities': None,
            'classes': None,
            'prediction': None,
            'method_used': None,
            'error': None
        }
        if est is None:
            result['error'] = 'Model not loaded'
            return result
        try:
            input_data = X if isinstance(X, (pd.DataFrame, pd.Series)) else np.asarray(X)
            if hasattr(est, 'classes_'):
                result['classes'] = list(est.classes_)
            if hasattr(est, "predict_proba"):
                p = est.predict_proba(input_data)
                result['method_used'] = 'predict_proba'
                result['all_probabilities'] = p[0].tolist()
                if p.ndim == 2 and p.shape[1] >= 2:
                    result['attack_probability'] = float(np.clip(p[0, -1], 0, 1))
                else:
                    result['attack_probability'] = float(np.clip(p[0, 0], 0, 1))
            elif hasattr(est, "decision_function"):
                d = est.decision_function(input_data)
                result['method_used'] = 'decision_function'
                result['attack_probability'] = float(1 / (1 + np.exp(-float(d[0]))))
                result['all_probabilities'] = [1 - result['attack_probability'], result['attack_probability']]
            elif hasattr(est, "predict"):
                y = est.predict(input_data)
                result['method_used'] = 'predict'
                result['prediction'] = str(y[0])
                if isinstance(y[0], (int, float, np.floating)):
                    result['attack_probability'] = float(y[0])
            # Always try binary prediction
            if hasattr(est, "predict"):
                y = est.predict(input_data)
                result['prediction'] = str(y[0])
        except Exception as e:
            result['error'] = str(e)
        return result

    # -------- DB --------
    def _should_save(self, proba_attack: Optional[float], proba_anomaly: Optional[float],
                     label_bin: Optional[str], threshold: float, log_all: bool) -> bool:
        if log_all: return True
        vote_attack = (proba_attack is not None and proba_attack >= threshold)
        vote_anom   = (proba_anomaly is not None and proba_anomaly >= max(threshold, 0.7))
        vote_label  = (label_bin is not None and label_bin.lower() not in ("normal","0"))
        return vote_attack or vote_label or vote_anom

    def _save_packet(self, row: Dict[str, Any], final_label: Optional[str],
                     proba_attack: Optional[float], proba_anomaly: Optional[float],
                     iface: Optional[str]):
        db = SessionLocal()
        try:
            ts_val = row.get("time_epoch")
            ts = float(ts_val) if ts_val == ts_val else time.time()
            pkt = Packet(
                ts=datetime.utcfromtimestamp(ts),
                iface=iface,
                src_mac=row.get("src_mac"), dst_mac=row.get("dst_mac"), bssid=row.get("bssid"),

                frame_len=int(row.get("frame.len")) if "frame.len" in row and row["frame.len"] == row["frame.len"] else None,
                channel_freq=int(row.get("radiotap.channel.freq")) if "radiotap.channel.freq" in row and row["radiotap.channel.freq"] == row["radiotap.channel.freq"] else None,
                datarate=float(row.get("radiotap.datarate")) if "radiotap.datarate" in row and row["radiotap.datarate"] == row["radiotap.datarate"] else None,
                signal_dbm=float(row.get("radiotap.dbm_antsignal")) if "radiotap.dbm_antsignal" in row and row["radiotap.dbm_antsignal"] == row["radiotap.dbm_antsignal"] else None,
                wlan_ds=int(row.get("wlan.fc.ds")) if "wlan.fc.ds" in row and row["wlan.fc.ds"] == row["wlan.fc.ds"] else None,
                wlan_retry=int(row.get("wlan.fc.retry")) if "wlan.fc.retry" in row and row["wlan.fc.retry"] == row["wlan.fc.retry"] else None,
                wlan_type=int(row.get("wlan.fc.type")) if "wlan.fc.type" in row and row["wlan.fc.type"] == row["wlan.fc.type"] else None,
                wlan_subtype=int(row.get("wlan.fc.subtype")) if "wlan.fc.subtype" in row and row["wlan.fc.subtype"] == row["wlan.fc.subtype"] else None,
                wlan_duration=int(row.get("wlan.duration")) if "wlan.duration" in row and row["wlan.duration"] == row["wlan.duration"] else None,

                proba_anomaly=proba_anomaly,
                proba_attack=proba_attack,
                predicted_label=final_label,
                raw=row
            )
            db.add(pkt); db.commit()
            self._saved += 1
            if final_label and final_label.lower() not in ("normal","0"):
                self._attacks += 1
        except Exception as e:
            db.rollback()
            print(f"[!] DB save failed: {e}")
        finally:
            db.close()

    # -------- run loop --------
    def _run(self):
        assert self._cfg is not None
        cfg = self._cfg
        self._started_at = time.time()

        print(f"[i] Starting pyshark capture on interface {cfg.iface}")
        self._capture = _create_pyshark_capture(cfg)
        if self._capture is None:
            print("[!] Failed to create pyshark capture - exiting")
            return
        print(f"[✓] Pyshark capture ready: {self._capture}")

        try:
            print("[i] Starting packet capture loop...")
            packets_iterator = self._capture.sniff_continuously()
            last_heartbeat = time.time()
            heartbeat_interval = 10

            for packet in packets_iterator:
                if self._stop.is_set():
                    print("[i] Stop signal received, breaking capture loop")
                    break

                now = time.time()
                if now - last_heartbeat >= heartbeat_interval:
                    print(f"[heartbeat] Capture running - seen {self._seen} packets")
                    last_heartbeat = now

                self._seen += 1

                if not hasattr(packet, 'wlan'):
                    continue

                # Optional SSID/BSSID filtering (extra safety in code)
                if hasattr(cfg, 'target_ssid') and cfg.target_ssid:
                    pkt_ssid = getattr(packet.wlan, 'ssid', None)
                    pkt_bssid = getattr(packet.wlan, 'bssid', None)
                    pkt_sa = getattr(packet.wlan, 'sa', None)
                    pkt_da = getattr(packet.wlan, 'da', None)

                    frame_type = getattr(packet.wlan, 'fc_type', None)
                    frame_subtype = getattr(packet.wlan, 'fc_subtype', None)
                    is_deauth = (frame_type == 0 and frame_subtype == 12)

                    if is_deauth:
                        # allow deauth if matches our BSSID in any role
                        if not (pkt_bssid == cfg.target_bssid or pkt_sa == cfg.target_bssid or pkt_da == cfg.target_bssid):
                            continue
                    else:
                        if (pkt_ssid != cfg.target_ssid and
                            pkt_bssid != cfg.target_bssid and
                            pkt_sa != cfg.target_bssid and
                            pkt_da != cfg.target_bssid):
                            continue

                parsed = _parse_pyshark_packet(packet)
                if not parsed:
                    continue

                # ----- Stage-1: build input and predict proba/label -----
                df1 = pd.DataFrame([{k: v for k, v in parsed.items() if k in FEATURES_STAGE1}])

                # Prepare X1:
                #  - If you have a separate preprocessor: use _transform
                #  - Else if classifier is a Pipeline: pass df1 as-is
                #  - Else cast to numeric
                if self.stage1_preproc is not None:
                    X1 = self._transform(df1, FEATURES_STAGE1, self.stage1_preproc)
                else:
                    X1 = self._prepare_input(df1, FEATURES_STAGE1, None, self.stage1_clf)

                # Detailed proba info
                stage1_proba_details = self._detailed_proba_from_estimator(self.stage1_clf, X1, "Stage1_Binary")
                proba_attack_raw = stage1_proba_details['attack_probability']

                # *** IMPORTANT CHANGE ***
                # Do NOT call apply_intelligent_override. Trust model output directly.
                proba_attack = proba_attack_raw

                # Binary label (fallback)
                label_bin = None
                if stage1_proba_details.get('prediction') is not None:
                    label_bin = stage1_proba_details['prediction']
                else:
                    label_bin = "1" if (proba_attack is not None and proba_attack > 0.5) else "0"

                # Optional anomaly model
                proba_anomaly = None
                if self.anomaly_model:
                    anomaly_details = self._detailed_proba_from_estimator(self.anomaly_model, X1, "Anomaly_Model")
                    proba_anomaly = anomaly_details['attack_probability']

                # Packet summaries for visibility
                ft = parsed.get("wlan.fc.type")
                fst = parsed.get("wlan.fc.subtype")
                frame_type_int = int(ft) if ft is not None and not pd.isna(ft) else None
                frame_subtype_int = int(fst) if fst is not None and not pd.isna(fst) else None

                def _ft_name(t, st):
                    if t == 0:
                        if st == 12: return "DEAUTH"
                        if st == 8:  return "BEACON"
                        if st in [0,1]: return "ASSOC"
                        return "MGMT"
                    if t == 1: return "CTRL"
                    if t == 2: return "DATA"
                    return "UNKNOWN"

                if (proba_attack is not None and proba_attack >= 0.3) or (self._seen % 100 == 0):
                    print(f"[PACKET #{self._seen}] type={_ft_name(frame_type_int, frame_subtype_int)} proba={None if proba_attack is None else round(proba_attack,4)}")

                # Decide to save
                is_attack = (proba_attack is not None and proba_attack >= cfg.proba_threshold)
                if is_attack:
                    print(f"[ATTACK DETECTED] Packet #{self._seen}: proba={proba_attack:.6f} >= threshold={cfg.proba_threshold}")

                if is_attack or cfg.log_all:
                    final_label = "attack" if is_attack else "normal"

                    # ----- Stage-2 (optional multiclass) -----
                    if is_attack and self.stage2_clf is not None:
                        # Stage-2 features may differ
                        stage2_feats = []
                        for feat in FEATURES_STAGE2:
                            stage2_feats.append(feat.replace('num__', '') if feat.startswith('num__') else feat)
                        df2 = pd.DataFrame([{k: v for k, v in parsed.items() if k in stage2_feats}])

                        if self.stage2_preproc is not None:
                            X2 = self._transform(df2, stage2_feats, self.stage2_preproc)
                        else:
                            X2 = self._prepare_input(df2, stage2_feats, None, self.stage2_clf)

                        stage2_details = self._detailed_proba_from_estimator(self.stage2_clf, X2, "Stage2_Multiclass")
                        final_label = stage2_details['prediction']
                        print(f"[STAGE2] classes={stage2_details.get('classes')} pred={final_label} probs={stage2_details.get('all_probabilities')}")

                    # Active defense (optional; keep behavior)
                    if is_attack:
                        send_deauth(parsed.get("src_mac"), parsed.get("bssid"), cfg.iface)

                    self._save_packet(parsed, final_label, proba_attack, proba_anomaly, cfg.iface)

        except Exception as e:
            print(f"[!] Error during packet capture: {e}")
        finally:
            if self._capture:
                try:
                    self._capture.close()
                except Exception:
                    pass
            self._capture = None

detector = Detector()
