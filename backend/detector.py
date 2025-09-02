# detector.py
# Two-stage live detector (PURE ML):
#   Stage-1 (binary, probas): attack vs normal  -> your classifier/preprocessor/feature list
#   Stage-2 (multiclass): runs ONLY if Stage-1 flags attack -> LightGBM bundle with:
#       model, best_iteration, num_imputer, scaler,
#       num_cols, cat_cols, cat_vocab, feature_order, class_order, id_to_class
#
# - No rule-based conditions. No overrides. We trust model outputs.
# - Stage-2 strictly follows your README.
#
# Hardenings & Debug:
# - Asserts Stage-1 loads (and has predict_proba or decision_function).
# - Heavy diagnostics for paths, features, pipelines, classes, and probabilities.
# - JSON sanitize (NaN/Inf -> None) before DB insert to satisfy JSON/JSONB.
# - Raw SQL path for Postgres (optional) + ORM path; both share the same SessionLocal.
# - Env toggles: DEBUG_DETECTOR, DEBUG_DB, DEBUG_PACKETS, ATTACK_POS_CLASS.
# - New envs:
#     REQUIRE_S1_PREPROC=1  -> if set, we must use Stage-1 preprocessor successfully
#     DEBUG_SANITY=1        -> extra checks on X1 variance/NaN coverage

import os, json, time, threading, glob, math
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

import numpy as np
import pandas as pd

from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import pyshark
from dotenv import load_dotenv

from sqlalchemy import text  # for raw SQL path

from db import SessionLocal, Packet
from schemas import DetectorConfig, DetectorStatus

try:
    import joblib
except Exception:
    joblib = None

load_dotenv()

# --- Debug toggles ---
DEBUG_DETECTOR = os.environ.get("DEBUG_DETECTOR", "0") == "1"   # heavy model/feature logs
DEBUG_DB       = os.environ.get("DEBUG_DB", "0") == "1"         # DB insert logs
DEBUG_PACKETS  = os.environ.get("DEBUG_PACKETS", "0") == "1"    # per-packet feature dumps
DEBUG_SANITY   = os.environ.get("DEBUG_SANITY", "0") == "1"

REQUIRE_S1_PREPROC = os.environ.get("REQUIRE_S1_PREPROC", "0") == "1"

def _tiny(df: pd.DataFrame, n=1):
    try:
        return df.head(n).to_dict(orient="records")
    except Exception:
        return str(df.head(n))

# =========================
# Utilities
# =========================

def send_deauth(src_mac, bssid, iface):
    """Send a deauth frame (use only where authorized)."""
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
    seen = set(); out=[]
    for x in seq:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

# =========================
# Paths and configuration
# =========================

# ---- Stage-1 (binary) artifacts ----
STAGE1_CLF_PATH = os.environ.get(
    "STAGE1_CLF_PATH",
    "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1/lbgm_binary.joblib"
)
STAGE1_PREPROC_PATH = os.environ.get(
    "STAGE1_PREPROCESSOR_PATH",
    "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1/preprocessor.joblib"
)  # optional
STAGE1_FEATURES_PATH = os.environ.get(
    "STAGE1_FEATURES_PATH",
    "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1/feature_names.json"
)  # optional JSON list

# ---- Stage-2 (multiclass) bundle ----
STAGE2_BUNDLE_PATH = os.environ.get(
    "STAGE2_BUNDLE_PATH",
    "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_2/multiclass_lightgbm_bundle.joblib"
)

# Optional anomaly model (not required)
ANOMALY_MODEL_PATH = os.environ.get("ANOMALY_MODEL_PATH")

# -------- Default Stage-1 Feature List (as provided) --------
USER_STAGE1_FEATURES = [
    "frame.encap_type","frame.len","frame.time_delta","frame.time_delta_displayed","frame.time_relative",
    "radiotap.channel.flags.cck","radiotap.channel.flags.ofdm","radiotap.channel.freq","radiotap.datarate",
    "radiotap.dbm_antsignal","radiotap.length","radiotap.rxflags","wlan.duration","wlan.fc.ds","wlan.fc.frag",
    "wlan.fc.order","wlan.fc.moredata","wlan.fc.protected","wlan.fc.pwrmgt","wlan.fc.type","wlan.fc.retry",
    "wlan.fc.subtype","wlan_radio.duration","wlan.seq","wlan_radio.channel","wlan_radio.data_rate",
    "wlan_radio.frequency","wlan_radio.signal_dbm","wlan_radio.phy","wlan.country_info.fnm","wlan.country_info.code",
]

def _load_feature_list(path: Optional[str], fallback: List[str]) -> List[str]:
    if path:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and all(isinstance(x, str) for x in data):
                print(f"[i] Loaded Stage-1 features from JSON: {path} (n={len(data)})")
                return data
            else:
                print(f"[i] Feature JSON is not a simple list of strings: {path}")
        except Exception as e:
            print(f"[i] Could not load features from {path}: {e}")
    return fallback

FEATURES_STAGE1 = _load_feature_list(STAGE1_FEATURES_PATH, USER_STAGE1_FEATURES)

# Always capture these extra fields for metadata/time
EXTRA_FIELDS = ["wlan.sa", "wlan.da", "wlan.bssid", "frame.time_epoch"]

# Mapping between radiotap and wlan_radio naming (best-effort)
MIRRORS = {
    "wlan_radio.data_rate": "radiotap.datarate",
    "wlan_radio.signal_dbm": "radiotap.dbm_antsignal",
    "wlan_radio.frequency": "radiotap.channel.freq",
    "wlan_radio.channel": "radiotap.channel.freq",
    "wlan_radio.duration": "wlan.duration",
}

# Which fields should be treated as binary flags
FLAG_LIKE = set([
    "radiotap.channel.flags.cck","radiotap.channel.flags.ofdm",
    "wlan.fc.ds","wlan.fc.frag","wlan.fc.order","wlan.fc.moredata",
    "wlan.fc.protected","wlan.fc.pwrmgt","wlan.fc.retry"
])

# =========================
# Packet Parsing
# =========================

def _parse_flag(v):
    if v is None or v == "": return 0
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
    """Parse a pyshark packet into a dict of features + meta (src/dst/bssid/time)."""
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

        # processed row (initialize all known fields as NaN) — TSHARK_FIELDS is set during artifact load
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
                    processed_row[f] = val

        # meta
        processed_row["src_mac"] = row.get("wlan.sa") or None
        processed_row["dst_mac"] = row.get("wlan.da") or None
        processed_row["bssid"]   = row.get("wlan.bssid") or None
        processed_row["time_epoch"] = _parse_numeric(row.get("frame.time_epoch"))
        return processed_row
    except Exception as e:
        print(f"[!] Failed to parse packet: {e}")
        return None

def _create_pyshark_capture(cfg: DetectorConfig):
    """Create a pyshark capture object with optional WPA decryption and SSID/BSSID filtering."""
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
        print(f"[i] Using filter: {display_filter}")
    else:
        print(f"[!] No SSID filter set - capturing all networks! Set TARGET_SSID or pass target_ssid in config.")

    try:
        print(f"[i] Creating pyshark capture on interface: {cfg.iface}")
        capture = pyshark.LiveCapture(
            interface=cfg.iface,
            display_filter=display_filter,
            custom_parameters=custom_params if custom_params else None
        )
        print(f"[✓] Pyshark capture created.")
        return capture
    except Exception as e:
        print(f"[!] Failed to create pyshark capture: {e}")
        return None

# =========================
# Stage-2 Bundle Helpers (per README)
# =========================

HEX_PREFIX = "0x"
NA_TOKEN = "__NA__"

def _coerce_numeric_scalar(v: Any) -> float:
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return np.nan
    s = str(v).strip()
    if s == "" or s == "?" or s.upper() == "NA":
        return np.nan
    if s.startswith(HEX_PREFIX):
        s = s[len(HEX_PREFIX):]
    try:
        return float(s)
    except Exception:
        return np.nan

def _coerce_categorical_scalar(v: Any, allowed: List[str]) -> str:
    if v is None:
        return NA_TOKEN
    s = str(v)
    if s == "" or s == "?":
        s = NA_TOKEN
    if s not in allowed:
        s = NA_TOKEN
    return s

# =========================
# [DIAG] Stage-1 Path Diagnostics & Resolution
# =========================

def _debug_path_info(p: str):
    print(f"[debug] STAGE1_CLF_PATH raw: {repr(p)}")
    try:
        rp = os.path.realpath(p)
        print(f"[debug] realpath: {rp}")
        print(f"[debug] exists? {os.path.exists(p)}  isfile? {os.path.isfile(p)}  isdir? {os.path.isdir(p)}")
        if os.path.exists(p):
            try:
                st = os.stat(p)
                print(f"[debug] size={st.st_size} bytes  perms={oct(st.st_mode)[-3:]}  uid={st.st_uid} gid={st.st_gid}")
            except Exception as e:
                print(f"[debug] os.stat failed: {e}")
        parent = os.path.dirname(p) or "."
        print(f"[debug] parent dir: {parent}")
        if os.path.isdir(parent):
            try:
                items = os.listdir(parent)
                print(f"[debug] parent contents ({len(items)}):")
                for name in items[:25]:
                    print("   -", name)
                if len(items) > 25:
                    print("   ...")
            except Exception as e:
                print(f"[debug] listdir failed: {e}")
    except Exception as e:
        print(f"[debug] path introspection failed: {e}")

def _resolve_stage1_path_or_die() -> str:
    # 1) honor env if it points to an existing file
    p_env = os.environ.get("STAGE1_CLF_PATH", "").strip()
    if p_env:
        _debug_path_info(p_env)
        if os.path.isfile(p_env):
            return p_env
        else:
            print("[warn] Env STAGE1_CLF_PATH set but not a file.")

    # 2) default constant
    default_p = "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1/lbgm_binary.joblib"
    _debug_path_info(default_p)
    if os.path.isfile(default_p):
        return default_p

    # 3) common candidates (typos / alternates)
    candidates = [
        "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1/lgbm_binary.joblib",
        "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1/model.joblib",
        "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1/model.pkl",
        "artifacts/stage_1/model.joblib",
        "artifacts/stage_1/model.pkl",
        "/mnt/data/binary_ids_lightgbm_bundle.joblib",
    ]
    for c in candidates:
        _debug_path_info(c)
        if os.path.isfile(c):
            print(f"[debug] Using candidate: {c}")
            return c

    # 4) glob search in likely roots
    roots = [
        "/home/smart/Desktop/projects-last/projects/iwps/backend/backend/artifacts/stage_1",
        "artifacts/stage_1",
        "/mnt/data",
    ]
    for r in roots:
        if os.path.isdir(r):
            hits = []
            for pat in ("*.joblib", "*.pkl"):
                hits.extend(glob.glob(os.path.join(r, pat)))
            if hits:
                hits.sort(key=lambda f: os.path.getmtime(f), reverse=True)
                print(f"[debug] Using most recent in {r}: {hits[0]}")
                return hits[0]

    raise RuntimeError(
        "[FATAL] Could not locate Stage-1 classifier anywhere I looked. "
        "Set STAGE1_CLF_PATH to an existing .joblib/.pkl or place it under artifacts/stage_1/ or /mnt/data/."
    )

# =========================
# [JSON_FIX] Sanitize NaN/Inf for JSON/JSONB
# =========================

def _json_sanitize(obj):
    """Recursively replace NaN/Inf in dict/list/np types with None; convert numpy scalars to Python types."""
    if obj is None:
        return None
    if isinstance(obj, (np.generic,)):
        obj = obj.item()
    if isinstance(obj, float):
        if math.isnan(obj) or math.isinf(obj):
            return None
        return obj
    if isinstance(obj, (int, str, bool)):
        return obj
    if isinstance(obj, dict):
        return {k: _json_sanitize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_sanitize(v) for v in obj]
    try:
        if pd.isna(obj):
            return None
    except Exception:
        pass
    return obj

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

        # Stage-2 bundle parts
        self.stage2_bundle_loaded = False
        self.stage2_model = None
        self.stage2_best_iter: Optional[int] = None
        self.stage2_num_imputer = None
        self.stage2_scaler = None
        self.stage2_num_cols: List[str] = []
        self.stage2_cat_cols: List[str] = []
        self.stage2_cat_vocab: Dict[str, List[str]] = {}
        self.stage2_feature_order: List[str] = []
        self.stage2_class_order: List[Any] = []
        self.stage2_id_to_class: Dict[int, str] = {}

        self.anomaly_model = None  # optional

        # Fields for capture
        self.FEATURES_STAGE1 = FEATURES_STAGE1.copy()
        self.TSHARK_FIELDS: List[str] = _unique(self.FEATURES_STAGE1 + EXTRA_FIELDS)

        # Diagnostics
        self._s1_expected_features: Optional[List[str]] = None  # from model.feature_names_in_ if any

        self._load_artifacts()

    # -------- reload support --------
    def reload_artifacts(self):
        self._load_artifacts()

    def _try_extract_estimator_features(self, est) -> Optional[List[str]]:
        """Try to read feature_names_in_ from either an estimator or the final step of a Pipeline."""
        try:
            if hasattr(est, "feature_names_in_"):
                return list(est.feature_names_in_)
            # Pipeline?
            if hasattr(est, "steps"):
                last_est = est.steps[-1][1]
                if hasattr(last_est, "feature_names_in_"):
                    return list(last_est.feature_names_in_)
            if hasattr(est, "named_steps"):
                # get last
                last_key = list(est.named_steps.keys())[-1]
                last_est = est.named_steps[last_key]
                if hasattr(last_est, "feature_names_in_"):
                    return list(last_est.feature_names_in_)
        except Exception:
            pass
        return None

    def _load_artifacts(self):
        # Stage-1 features (allow JSON override)
        self.FEATURES_STAGE1 = _load_feature_list(STAGE1_FEATURES_PATH, USER_STAGE1_FEATURES)
        print(f"[i] Stage-1 features: {len(self.FEATURES_STAGE1)} → {self.FEATURES_STAGE1}")

        if joblib is None:
            raise RuntimeError("[FATAL] joblib not available in environment.")

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

        # Stage-1 classifier (Pipeline or plain model)
        try:
            stage1_path = _resolve_stage1_path_or_die()
            self.stage1_clf = joblib.load(stage1_path)
            print("[✓] Stage-1 classifier:", stage1_path)
            if DEBUG_DETECTOR:
                print("[debug:stage1] loaded type:", type(self.stage1_clf))
                if hasattr(self.stage1_clf, "classes_"):
                    print("[debug:stage1] classes_:", getattr(self.stage1_clf, "classes_"))
        except Exception as e:
            self.stage1_clf = None
            raise RuntimeError(f"[FATAL] Failed to load Stage-1 classifier: {e}")

        # Capture expected features (if estimator exposes them)
        self._s1_expected_features = self._try_extract_estimator_features(self.stage1_clf)
        if DEBUG_DETECTOR and self._s1_expected_features is not None:
            print(f"[debug:stage1] feature_names_in_ (n={len(self._s1_expected_features)}): {self._s1_expected_features[:20]}{'...' if len(self._s1_expected_features)>20 else ''}")

        # Assert probabilistic
        has_proba = hasattr(self.stage1_clf, "predict_proba")
        has_decfn = hasattr(self.stage1_clf, "decision_function")
        print(f"[debug] Stage-1 type: {type(self.stage1_clf)}")
        print(f"[debug] Stage-1 has predict_proba? {has_proba}  decision_function? {has_decfn}")
        if not (has_proba or has_decfn):
            raise RuntimeError("[FATAL] Stage-1 model exposes neither predict_proba nor decision_function. Export a probabilistic model or wrap it with CalibratedClassifierCV.")

        # Stage-2 bundle
        self.stage2_bundle_loaded = False
        try:
            if STAGE2_BUNDLE_PATH and os.path.exists(STAGE2_BUNDLE_PATH):
                bundle = joblib.load(STAGE2_BUNDLE_PATH)
                for k in ["model", "best_iteration", "num_imputer", "scaler",
                          "num_cols", "cat_cols", "cat_vocab", "feature_order",
                          "class_order", "id_to_class"]:
                    if k not in bundle:
                        raise KeyError(f"Stage-2 bundle missing key: {k}")

                self.stage2_model = bundle["model"]
                self.stage2_best_iter = bundle["best_iteration"]
                self.stage2_num_imputer = bundle["num_imputer"]
                self.stage2_scaler = bundle["scaler"]
                self.stage2_num_cols = list(bundle["num_cols"])
                self.stage2_cat_cols = list(bundle["cat_cols"])
                self.stage2_cat_vocab = dict(bundle["cat_vocab"])
                self.stage2_feature_order = list(bundle["feature_order"])
                self.stage2_class_order = list(bundle["class_order"])
                self.stage2_id_to_class = {int(k): v for k, v in dict(bundle["id_to_class"]).items()}
                self.stage2_bundle_loaded = True
                print("[✓] Stage-2 bundle:", STAGE2_BUNDLE_PATH)
                if DEBUG_DETECTOR:
                    print("[debug:stage2] keys loaded:",
                          "num_cols", len(self.stage2_num_cols),
                          "cat_cols", len(self.stage2_cat_cols),
                          "feature_order", len(self.stage2_feature_order),
                          "classes", self.stage2_class_order)
            else:
                print("[i] Stage-2 bundle not found:", STAGE2_BUNDLE_PATH)
        except Exception as e:
            print(f"[!] Failed to load Stage-2 bundle: {e}")
            self.stage2_bundle_loaded = False

        # Recompute fields to capture
        if self.stage2_bundle_loaded:
            union_fields = _unique(self.FEATURES_STAGE1 + self.stage2_feature_order + EXTRA_FIELDS)
        else:
            union_fields = _unique(self.FEATURES_STAGE1 + EXTRA_FIELDS)
        self.TSHARK_FIELDS = union_fields
        global TSHARK_FIELDS
        TSHARK_FIELDS = self.TSHARK_FIELDS

        print(f"[i] tshark fields (n={len(self.TSHARK_FIELDS)}).")
        print("="*60)

        # Optional anomaly
        try:
            if ANOMALY_MODEL_PATH and os.path.exists(ANOMALY_MODEL_PATH):
                self.anomaly_model = joblib.load(ANOMALY_MODEL_PATH)
                print("[✓] Anomaly model:", ANOMALY_MODEL_PATH)
        except Exception as e:
            print(f"[!] Failed to load anomaly model: {e}")

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

    # -------- DataFrame & debug helpers (Stage-1)
    def _ensure_columns(self, df: pd.DataFrame, cols: List[str]) -> pd.DataFrame:
        missing_cols = []
        for c in cols:
            if c not in df.columns:
                df[c] = np.nan
                missing_cols.append(c)
        if missing_cols:
            print(f"[FEATURE_WARNING] Added {len(missing_cols)} missing columns with NaN: {missing_cols[:10]}{'...' if len(missing_cols) > 10 else ''}")
        return df[cols]

    def _align_to_expected(self, df: pd.DataFrame, est) -> pd.DataFrame:
        """If estimator exposes feature_names_in_, reindex to that order and warn on missing/extra."""
        expected = self._s1_expected_features
        if not expected:
            return df
        extra = [c for c in df.columns if c not in expected]
        missing = [c for c in expected if c not in df.columns]
        if extra:
            print(f"[feature-align] extra columns ignored (not in model): {extra[:10]}{'...' if len(extra)>10 else ''}")
        if missing:
            print(f"[feature-align] missing columns for model (filled NaN): {missing[:10]}{'...' if len(missing)>10 else ''}")
        for c in missing:
            df[c] = np.nan
        return df.reindex(columns=expected)

    def _prepare_input(self, df: pd.DataFrame, features: List[str], preproc, est) -> pd.DataFrame:
        df = self._ensure_columns(df, features)
        df = self._align_to_expected(df, est)
        # If there's NO separate preproc and the estimator is a Pipeline, pass raw df (Pipeline handles it)
        if preproc is None and (hasattr(est, "steps") or hasattr(est, "named_steps")):
            return df
        # Otherwise, cast numeric/NaN-safe
        return df.astype("float32").fillna(0)

    def _transform(self, df: pd.DataFrame, features: List[str], preproc) -> pd.DataFrame:
        df = self._ensure_columns(df, features)
        df = self._align_to_expected(df, self.stage1_clf)
        if preproc is not None:
            try:
                X = preproc.transform(df)
                if isinstance(X, np.ndarray):
                    return pd.DataFrame(X, columns=[f'feature_{i}' for i in range(X.shape[1])])
                return X
            except Exception as e:
                print(f"[!] preprocessor.transform failed: {e}")
                if REQUIRE_S1_PREPROC:
                    raise RuntimeError("[FATAL] REQUIRE_S1_PREPROC=1 and Stage-1 preprocessor failed. Refusing to continue with a degraded input.")
                # degraded fallback
                return df.astype("float32").fillna(0)
        return df.astype("float32").fillna(0)

    def _sanity_check_X1(self, df1: pd.DataFrame, X1):
        if not DEBUG_SANITY:
            return
        try:
            arr = X1.values if hasattr(X1, "values") else np.asarray(X1)
            if arr.ndim == 2 and arr.shape[0] >= 1:
                row = arr[0]
                non_nan = np.count_nonzero(~np.isnan(row))
                zeros = np.count_nonzero(row == 0)
                n = row.size
                if n > 0:
                    nan_ratio = 1.0 - (non_nan / n)
                    zero_ratio = zeros / n
                    if nan_ratio > 0.6:
                        print(f"[sanity] WARNING: {nan_ratio:.0%} NaNs in X1 row")
                    if zero_ratio > 0.9:
                        print(f"[sanity] WARNING: {zero_ratio:.0%} zeros in X1 row (likely degraded features)")
        except Exception:
            pass

    def _debug_stage1_inputs(self, df1: pd.DataFrame, X1):
        if not DEBUG_DETECTOR:
            return
        print("[debug:features] df1 columns (first row):", _tiny(df1, 1))
        print("[debug:features] df1 dtypes:", {c: str(df1[c].dtype) for c in df1.columns})
        nan_counts = {c: int(df1[c].isna().sum()) for c in df1.columns}
        if any(nan_counts.values()):
            print("[debug:features] NaN counts:", {k: v for k, v in nan_counts.items() if v})
        if hasattr(self.stage1_clf, "steps"):
            print("[debug:pipeline] steps:", [name for name, _ in self.stage1_clf.steps])
        elif hasattr(self.stage1_clf, "named_steps"):
            print("[debug:pipeline] named_steps keys:", list(self.stage1_clf.named_steps.keys()))
        try:
            shape = getattr(X1, "shape", None)
            print(f"[debug:features] X1 type={type(X1)} shape={shape}")
        except Exception:
            pass
        self._sanity_check_X1(df1, X1)

    # -------- Estimator helpers (Stage-1 / anomaly)
    @staticmethod
    def _proba_from_estimator_raw(est, X):
        """Return (proba_vector, classes_list or None)."""
        try:
            input_data = X if isinstance(X, (pd.DataFrame, pd.Series)) else np.asarray(X)
            classes = getattr(est, "classes_", None)
            if hasattr(est, "predict_proba"):
                p = est.predict_proba(input_data)
                if DEBUG_DETECTOR:
                    print(f"[debug:stage1] predict_proba shape={np.shape(p)} classes={classes}")
                return p, list(classes) if classes is not None else None
            if hasattr(est, "decision_function"):
                d = est.decision_function(input_data)
                if DEBUG_DETECTOR:
                    print(f"[debug:stage1] decision_function shape={np.shape(d)} (sigmoid will be applied)")
                d0 = float(np.atleast_1d(d)[0])
                p = np.array([[1/(1+np.exp(d0)), 1/(1+np.exp(-d0))]])
                return p, [0, 1]
            if hasattr(est, "predict"):
                y = est.predict(input_data)
                if DEBUG_DETECTOR:
                    print(f"[debug:stage1] predict only -> y[0]={y[0]}")
                y0 = y[0]
                if isinstance(y0, (int, float, np.integer, np.floating)):
                    p = np.array([[1-float(y0), float(y0)]])
                    return p, [0, 1]
                p = np.array([[0.0, 1.0 if str(y0).lower()=="attack" else 0.0]])
                return p, ["normal","attack"]
        except Exception as e:
            print(f"[!] _proba_from_estimator_raw failed: {e}")
        return None, None

    @staticmethod
    def _pick_attack_prob(p_vec, classes):
        """Choose P(attack) from a probability vector + classes."""
        if p_vec is None:
            return None
        p_vec = np.asarray(p_vec)
        v = p_vec[0] if p_vec.ndim == 2 else p_vec

        if classes is None:
            return float(np.clip(float(np.max(v)), 0, 1))

        def _norm(c):
            try:
                return int(c)
            except Exception:
                return str(c).lower()

        cls = [_norm(c) for c in classes]

        raw = os.environ.get("ATTACK_POS_CLASS", "").strip()
        if raw:
            try:
                tgt = int(raw)
            except Exception:
                tgt = raw.lower()
            if tgt in cls:
                return float(np.clip(v[cls.index(tgt)], 0, 1))

        if "attack" in cls:
            return float(np.clip(v[cls.index("attack")], 0, 1))
        if 1 in cls and len(cls) >= 2:
            return float(np.clip(v[cls.index(1)], 0, 1))
        if set(cls) <= {0, 1}:
            return float(np.clip(v[cls.index(1)], 0, 1))
        return float(np.clip(float(np.max(v)), 0, 1))

    @staticmethod
    def _predict_label_from_estimator(est, X) -> Optional[str]:
        if est is None: return None
        try:
            input_data = X if isinstance(X, (pd.DataFrame, pd.Series)) else np.asarray(X)
            if hasattr(est, "predict"):
                y = est.predict(input_data)
                return str(y[0])
        except Exception as e:
            print(f"[!] predict label failed: {e}")
        return None

    # -------- Stage-2 preprocessing (bundle spec)
    def _stage2_build_frame_from_rows(self, rows: List[Dict[str, Any]]) -> pd.DataFrame:
        X = pd.DataFrame(rows)
        for c in self.stage2_feature_order:
            if c not in X.columns:
                X[c] = np.nan
        X = X[self.stage2_feature_order]
        X = X.replace("?", np.nan)

        if len(self.stage2_num_cols) > 0:
            for c in self.stage2_num_cols:
                X[c] = X[c].apply(_coerce_numeric_scalar)
            NUM = pd.DataFrame(X[self.stage2_num_cols].values, columns=self.stage2_num_cols, index=X.index)
            NUM_arr = self.stage2_num_imputer.transform(NUM.values)
            NUM_arr = self.stage2_scaler.transform(NUM_arr)
            NUM = pd.DataFrame(NUM_arr, columns=self.stage2_num_cols, index=X.index)
        else:
            NUM = pd.DataFrame(index=X.index)

        if len(self.stage2_cat_cols) > 0:
            for c in self.stage2_cat_cols:
                allowed = self.stage2_cat_vocab.get(c, [NA_TOKEN])
                X[c] = X[c].apply(lambda v: _coerce_categorical_scalar(v, allowed))
                X[c] = pd.Categorical(X[c], categories=allowed, ordered=False)

        for c in self.stage2_num_cols:
            X[c] = NUM[c].astype(float)

        X = X[self.stage2_feature_order]
        return X

    def _stage2_predict_row(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.stage2_bundle_loaded:
            return None
        df = pd.DataFrame([row])
        X = self._stage2_build_frame_from_rows(df.to_dict(orient="records"))
        probs = self.stage2_model.predict(X, num_iteration=self.stage2_best_iter)  # shape [1, K]
        if probs.ndim != 2 or probs.shape[0] != 1:
            raise ValueError(f"Stage-2 model returned invalid probs shape: {probs.shape}")
        k = int(np.argmax(probs[0]))
        label = self.stage2_id_to_class.get(k, str(k))
        conf = float(probs[0, k])
        per_class = {self.stage2_id_to_class.get(i, str(i)): float(probs[0, i]) for i in range(probs.shape[1])}
        return {"label": label, "confidence": conf, "per_class": per_class}

    # -------- DB --------
    def _should_save(self, proba_attack: Optional[float], proba_anomaly: Optional[float],
                     label_bin: Optional[str], threshold: float, log_all: bool) -> bool:
        if log_all: return True
        vote_attack = (proba_attack is not None and proba_attack >= threshold)
        vote_anom   = (proba_anomaly is not None and proba_anomaly >= max(threshold, 0.7))
        vote_label  = (label_bin is not None and label_bin.lower() not in ("normal","0"))
        return vote_attack or vote_label or vote_anom

    def _save_packet_raw(self, row, final_label, proba_attack, proba_anomaly, iface, stage2_info=None):
        print(row)
        s = SessionLocal()
        try:
            # detect dialect
            bind = s.get_bind()  # Engine
            is_pg = bind.dialect.name in ("postgresql", "postgres")

            # ts
            ts_val = row.get("time_epoch")
            ts = float(ts_val) if isinstance(ts_val, (int, float)) and not math.isnan(ts_val) else time.time()
            ts_dt = datetime.utcfromtimestamp(ts)

            # sanitize raw JSON (no NaN/Inf)
            raw = dict(row)
            if stage2_info is not None:
                raw["_stage2"] = stage2_info
            raw = _json_sanitize(raw)
            raw_json = json.dumps(raw, ensure_ascii=False, allow_nan=False)

            def _int(x):
                try:
                    return int(x) if x == x else None
                except Exception:
                    return None
            def _float(x):
                try:
                    return float(x) if x == x else None
                except Exception:
                    return None

            params = {
                "ts": ts_dt,
                "iface": iface,
                "src_mac": row.get("src_mac"),
                "dst_mac": row.get("dst_mac"),
                "bssid": row.get("bssid"),
                "frame_len": _int(row.get("frame.len")),
                "channel_freq": _int(row.get("radiotap.channel.freq")),
                "datarate": _float(row.get("radiotap.datarate")),
                "signal_dbm": _float(row.get("radiotap.dbm_antsignal")),
                "wlan_ds": _int(row.get("wlan.fc.ds")),
                "wlan_retry": _int(row.get("wlan.fc.retry")),
                "wlan_type": _int(row.get("wlan.fc.type")),
                "wlan_subtype": _int(row.get("wlan.fc.subtype")),
                "wlan_duration": _int(row.get("wlan.duration")),
                "proba_anomaly": _float(proba_anomaly) if proba_anomaly is not None else None,
                "proba_attack": _float(proba_attack) if proba_attack is not None else None,
                "predicted_label": final_label,
                "raw_json": raw_json,
            }

            if is_pg:
                sql = text("""
                    INSERT INTO packets
                    (ts, iface, src_mac, dst_mac, bssid,
                    frame_len, channel_freq, datarate, signal_dbm,
                    wlan_ds, wlan_retry, wlan_type, wlan_subtype, wlan_duration,
                    proba_anomaly, proba_attack, predicted_label, raw)
                    VALUES
                    (:ts, :iface, :src_mac, :dst_mac, :bssid,
                    :frame_len, :channel_freq, :datarate, :signal_dbm,
                    :wlan_ds, :wlan_retry, :wlan_type, :wlan_subtype, :wlan_duration,
                    :proba_anomaly, :proba_attack, :predicted_label, CAST(:raw_json AS JSONB))
                    RETURNING id
                """)
            else:
                sql = text("""
                    INSERT INTO packets
                    (ts, iface, src_mac, dst_mac, bssid,
                    frame_len, channel_freq, datarate, signal_dbm,
                    wlan_ds, wlan_retry, wlan_type, wlan_subtype, wlan_duration,
                    proba_anomaly, proba_attack, predicted_label, raw)
                    VALUES
                    (:ts, :iface, :src_mac, :dst_mac, :bssid,
                    :frame_len, :channel_freq, :datarate, :signal_dbm,
                    :wlan_ds, :wlan_retry, :wlan_type, :wlan_subtype, :wlan_duration,
                    :proba_anomaly, :proba_attack, :predicted_label, :raw_json)
                """)

            # Execute on the Session (2.0 style)
            with s.begin():  # transactional scope
                res = s.execute(sql, params)
                if is_pg:
                    inserted_id = res.scalar_one()
                    if os.environ.get("DEBUG_DB"):
                        print(f"[debug:db] raw insert id={inserted_id}")

            self._saved += 1
            if final_label and final_label.lower() not in ("normal", "0"):
                self._attacks += 1

        except Exception as e:
            print(f"[!] DB raw insert failed: {e}")
        finally:
            s.close()

    def _save_packet(self, row: Dict[str, Any], final_label: Optional[str],
                     proba_attack: Optional[float], proba_anomaly: Optional[float],
                     iface: Optional[str], stage2_info: Optional[Dict[str, Any]] = None):
        db = SessionLocal()
        try:
            ts_val = row.get("time_epoch")
            ts = float(ts_val) if ts_val == ts_val else time.time()

            raw = dict(row)
            if stage2_info is not None:
                raw["_stage2"] = stage2_info
            raw = _json_sanitize(raw)  # JSON-safe

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
                raw=raw
            )

            db.add(pkt)
            if DEBUG_DB:
                print("[debug:db] before commit; ts=", datetime.utcfromtimestamp(ts))
            db.flush()
            if DEBUG_DB:
                print(f"[debug:db] assigned id={pkt.id}")
            db.commit()
            if DEBUG_DB:
                print(f"[debug:db] committed id={pkt.id} label={final_label} proba={proba_attack}")
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

        self._capture = _create_pyshark_capture(cfg)
        if self._capture is None:
            print("[!] Failed to create pyshark capture - exiting")
            return

        print("[i] Starting packet capture loop...")
        try:
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

                # Optional SSID/BSSID fine filtering
                if hasattr(cfg, 'target_ssid') and cfg.target_ssid:
                    pkt_ssid = getattr(packet.wlan, 'ssid', None)
                    pkt_bssid = getattr(packet.wlan, 'bssid', None)
                    pkt_sa = getattr(packet.wlan, 'sa', None)
                    pkt_da = getattr(packet.wlan, 'da', None)

                    frame_type = getattr(packet.wlan, 'fc_type', None)
                    frame_subtype = getattr(packet.wlan, 'fc_subtype', None)
                    is_deauth = (frame_type == 0 and frame_subtype == 12)

                    if is_deauth:
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
                df1 = pd.DataFrame([{k: v for k, v in parsed.items() if k in self.FEATURES_STAGE1}])

                if self.stage1_preproc is not None:
                    X1 = self._transform(df1, self.FEATURES_STAGE1, self.stage1_preproc)
                else:
                    X1 = self._prepare_input(df1, self.FEATURES_STAGE1, None, self.stage1_clf)

                self._debug_stage1_inputs(df1, X1)

                p_vec, classes = self._proba_from_estimator_raw(self.stage1_clf, X1)
                if DEBUG_DETECTOR and p_vec is not None:
                    if (self._seen % 25 == 1) or (self._seen < 5):
                        try:
                            print(f"[debug:stage1] classes={classes} probs={np.round(p_vec, 4).tolist()}")
                        except Exception:
                            pass

                proba_attack = self._pick_attack_prob(p_vec, classes)
                label_bin = self._predict_label_from_estimator(self.stage1_clf, X1)
                if label_bin is None:
                    label_bin = "1" if (proba_attack is not None and proba_attack > 0.5) else "0"

                # Optional anomaly model
                proba_anomaly = self._proba_from_estimator_raw(self.anomaly_model, X1)[0] if self.anomaly_model else None
                if isinstance(proba_anomaly, np.ndarray):
                    proba_anomaly = float(np.max(proba_anomaly[0]))  # coarse anomaly score if vector

                # Logs
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

                # If Stage-1 produced no probability, skip Stage-2 for this packet
                if proba_attack is None:
                    print("[FATAL] Stage-1 produced no probability — check model path/preprocessor. Skipping Stage-2 for this packet.")
                    continue

                # Stage-1 gate
                is_attack = (proba_attack >= cfg.proba_threshold)
                final_label = "attack" if is_attack else "normal"
                stage2_info = None

                if is_attack:
                    print(f"[ATTACK DETECTED] Packet #{self._seen}: proba={proba_attack:.6f} >= threshold={cfg.proba_threshold}")

                    # ----- Stage-2 (multiclass via bundle) -----
                    if self.stage2_bundle_loaded:
                        try:
                            stage2_info = self._stage2_predict_row(parsed)
                            if stage2_info is not None:
                                final_label = stage2_info["label"]
                                print(f"[STAGE2] pred={final_label} conf={stage2_info['confidence']:.4f}")
                        except Exception as e:
                            print(f"[!] Stage-2 prediction failed: {e}")

                    # Active defense
                    if not parsed.get("bssid") or not parsed.get("src_mac") or not cfg.iface:
                        if DEBUG_PACKETS:
                            print("[debug:deauth] src/bssid missing for frame:", {
                                "src_mac": parsed.get("src_mac"),
                                "bssid": parsed.get("bssid"),
                                "dst_mac": parsed.get("dst_mac"),
                                "type": parsed.get("wlan.fc.type"),
                                "subtype": parsed.get("wlan.fc.subtype"),
                            })
                    send_deauth(parsed.get("src_mac"), parsed.get("bssid"), cfg.iface)

                # Save if attack or log_all
                if is_attack or cfg.log_all:
                    self._save_packet(parsed, final_label, proba_attack, proba_anomaly, cfg.iface, stage2_info)
                    self._save_packet_raw(parsed, final_label, proba_attack, proba_anomaly, cfg.iface, stage2_info)

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
