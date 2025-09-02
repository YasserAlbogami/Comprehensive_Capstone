# Wi-Fi Intrusion Detection

## 👥 Team Members

| Name         |
| ------------ |
| **Haya**     |
| **Ghala**    |
| **Lena**     |
| **Mohammed** |
| **Yasser**   |

---

## 📌 Overview

This project builds an **Intrusion Detection System (IDS)** that captures Wi-Fi packets, extracts tabular features, and classifies them using a **two-stage LightGBM pipeline**.
It provides **real-time monitoring, attack statistics, and mitigation actions** through a **dashboard**, and integrates a **RAG module** to summarize results and explain the meaning of different attacks.

---

## 🎯 Target Attack Types

The IDS detects and classifies the following **six Wi-Fi attack types**:

- **SSDP**
- **Evil_Twin**
- **Krack**
- **Deauth**
- **(Re)Assoc**
- **RogueAP**

---

## 🧠 Model Architecture — Two-Stage LightGBM Pipeline

```
           ┌─────────────── Live Packet ───────────────┐
           │        Extract tabular features            │
           └─────────────────────┬──────────────────────┘
                                 ▼
                        Stage 1: Binary Classifier
                     (0 = Normal, 1 = Attack, LightGBM)
                                 │
             ┌───────────────────┴───────────────────┐
             │                                       │
           Normal                                 Attack
             │                                       ▼
             ▼                         Stage 2: Multiclass Classifier
        Doesn't concern us            (SSDP / Evil_Twin / Krack / Deauth /
                                        (Re)Assoc / RogueAP, LightGBM)
```

---

## 🚀 Phase 1 — Data & Feature Engineering

1. **Collect Data**: Normal + attack PCAPs.
2. **Extract Features**: e.g., `frame.len`, `delta_t`, subtype flags, broadcast indicators, sequence gaps, RSSI, channel.
3. **Labels**:

   - **Binary dataset** → `y_bin ∈ {0=Normal, 1=Attack}`
   - **Attack-only dataset** → `y_multi ∈ {SSDP, Evil_Twin, Krack, Deauth, (Re)Assoc, RogueAP}`

---

## 🏗️ Phase 2 — Training the Models

- **Binary classifier:** LightGBM, detects Attack vs Normal.
- **Multiclass classifier:** LightGBM, identifies one of the six attack types.

**Evaluation Metrics**:

- Binary → Accuracy, F1, ROC-AUC.
- Multiclass → Macro-F1, per-class precision/recall, confusion matrix.

---

## ⚙️ Phase 3 — Hardware Integration

- **Device:** Jetson TX1 + Alpha adapter (monitor mode).
- **Pipeline:** capture packets → extract features → binary classifier → (if attack) multiclass classifier.
- **Mitigation:** log alerts, block malicious MACs, or notify WLAN controller.

---

## 📖 Phase 4 — RAG Summarization & Explanations

The **RAG module** is designed to **summarize detection statistics** and provide **clear definitions of attack types**.

### Capabilities

- Answer: **“How many Deauth attacks did we see today?”**
- Provide: **“What is an Evil_Twin attack?”** (definition + short description).
- Summarize: number of attacks per type, per time window.

### Example Queries

- “Total number of attacks in the last hour.”
- “Show the breakdown of SSDP vs Evil_Twin.”
- “Define Krack attack.”

This makes the IDS **explainable** and easy for operators to interpret.

---

## 💻 Phase 5 — Dashboard (FastAPI + Frontend)

- **Backend (FastAPI):**

  - WebSocket for live results.
  - `/ask` endpoint for RAG queries.

- **Frontend (React/Next.js):**

  - Real-time attack feed.
  - RAG panel for summaries and definitions.
  - Policy editor for auto-responses.

---

## ✅ Final Output

- **Two-stage LightGBM IDS** for real-time Wi-Fi attack detection.
- **Dashboard** with live monitoring and RAG-powered summaries.
- Operators can see:

  - Attack counts over time.
  - Distribution by type.
  - Definitions of each attack.
