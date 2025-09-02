# predict_rawbytes.py
# ---------------------------------------------------------
# يتنبأ بفئة هجوم Wi-Fi من ملف .pcap/.pcapng:
# - يستخرج raw bytes لكل باكِت
# - يحوّلها إلى متجهات بطول ثابت (بنفس طول التدريب)
# - يطبّق البايبلاين المدّرب (Scaler + SVM)
# - يطبع تصويت أغلبية + نسبة الثقة

import argparse
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
import joblib

# --- نفس دوال التحويل المستخدمة في التدريب (مختصرة هنا) ---

def to_fixed_length_byte_vector(b: bytes, fixed_len: int) -> np.ndarray:
    arr = np.frombuffer(b, dtype=np.uint8)
    if arr.size >= fixed_len:
        return arr[:fixed_len]
    out = np.zeros(fixed_len, dtype=np.uint8)
    out[:arr.size] = arr
    return out

def _try_pyshark_bytes(pcap_path: Path, max_packets=None):
    import pyshark
    cap = pyshark.FileCapture(str(pcap_path), custom_parameters=['-x'], use_json=True, include_raw=True, keep_packets=False)
    out = []
    try:
        for pkt in cap:
            raw = None
            if hasattr(pkt, "get_raw_packet"):
                try:
                    raw = pkt.get_raw_packet()
                except Exception:
                    raw = None
            if raw is None:
                try:
                    hexstr = str(pkt.frame_raw.value)  # type: ignore
                    raw = bytes.fromhex(hexstr)
                except Exception:
                    raw = None
            if raw:
                out.append(raw)
                if max_packets and len(out) >= max_packets:
                    break
    finally:
        try: cap.close()
        except Exception: pass
    return out

def _try_scapy_bytes(pcap_path: Path, max_packets=None):
    from scapy.all import rdpcap  # type: ignore
    pkts = rdpcap(str(pcap_path))
    out = []
    for i, pkt in enumerate(pkts):
        raw = bytes(pkt.original) if hasattr(pkt, "original") else bytes(pkt)
        if raw:
            out.append(raw)
        if max_packets and (i+1) >= max_packets:
            break
    return out

def extract_raw_packets(pcap_path: Path, max_packets=None):
    try:
        return _try_pyshark_bytes(pcap_path, max_packets) or _try_scapy_bytes(pcap_path, max_packets)
    except Exception:
        return _try_scapy_bytes(pcap_path, max_packets)


def main():
    ap = argparse.ArgumentParser(description="Predict Wi-Fi attack class from raw packet bytes")
    ap.add_argument("pcap_path", type=str, help="مسار ملف .pcapng / .pcap")
    ap.add_argument("--model", type=str, default="svm_rawbytes_classifier.joblib", help="ملف الموديل المدرب")
    ap.add_argument("--fixed_len", type=int, default=None, help="طول المتجه (اتركه فارغاً ليُقرأ من الموديل)")
    ap.add_argument("--max_packets", type=int, default=None, help="حد أقصى لعدد الباكِتات (اختياري)")
    args = ap.parse_args()

    bundle = joblib.load(args.model)
    clf = bundle["pipeline"]
    feature_columns = bundle["feature_columns"]
    fixed_len = int(args.fixed_len or bundle["fixed_len"])

    raw_packets = extract_raw_packets(Path(args.pcap_path), max_packets=args.max_packets)
    if not raw_packets:
        raise RuntimeError("لم أستطع استخراج أي باكِت من الملف.")

    rows = [to_fixed_length_byte_vector(b, fixed_len=fixed_len) for b in raw_packets]
    X = pd.DataFrame(np.vstack(rows), columns=feature_columns)

    preds = clf.predict(X)
    counts = Counter(preds)
    total = sum(counts.values())
    top2 = counts.most_common(2)
    final_label, final_count = top2[0]
    # إن كان SVM مفعّل فيه probability=True (في التدريب)، نقدر نأخذ متوسط أعلى احتمال
    try:
        proba = clf.predict_proba(X).max(axis=1).mean()
        conf_txt = f"(ثقة متوسطة تقريبية {proba:.1%})"
    except Exception:
        conf_txt = ""

    print(f"🔹 عدد الباكِتات: {total}")
    print("🔹 أعلى الفئات:")
    for lbl, cnt in top2:
        print(f"   - {lbl}: {cnt} ({cnt/total:.1%})")
    print(f"✅ التوقع النهائي: {final_label} {conf_txt}")


if __name__ == "__main__":
    main()
