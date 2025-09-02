# 🔒 Wi-Fi Intrusion Detection System

**Wi-Fi Intrusion Prevention System (IDS)** is a lightweight, real-time security platform designed to monitor wireless networks, detect malicious activities, and classify common Wi-Fi attacks using **Machine Learning** and **RAG-based analysis**.

---

## 🌟 Features

- 📡 Real-time 802.11 packet capture in monitor mode
- 🤖 ML-based classifiers (Binary + Multi-class LightGBM)
- 🧠 AI assistant summaries and explanations of attacks
- 📊 Dashboard for live monitoring & attack statistics
- ⚡ Lightweight deployment on **Jetson TX1** / **Raspberry Pi 4**
- 🔐 Logs & incident reporting

---

## 🚀 Tech Stack

- **Python (FastAPI / Streamlit)** – APIs & Dashboard  
- **Scikit-learn / LightGBM** – Attack classification  
- **SQLite / PostgreSQL** – Data storage  
- **Pyshark** – Live packet capture  
- **Raspberry Pi 5** – Edge deployment hardware  

---

## 📡 API Endpoints

### 📦 Packets & Analytics

| Method | Endpoint            | Description                                                |
|-------:|---------------------|------------------------------------------------------------|
| GET    | `/attacks`          | Raw dump of packets table (paginated, newest first).       |
| GET    | `/packets/count`    | Total number of rows in packets.                           |
| GET    | `/attacks/analysis` | Count by predicted_label for the six known attack types.   |
| GET    | `/top-offenders`    | Top sources by MAC address.                                |
| GET    | `/channel-usage`    | Channel usage by frequency.                                |
| GET    | `/heatmap-attack`   | Week-day × hour heatmap (UTC) from timestamps.             |

### 🛠️ Detector Control

| Method | Endpoint           | Description                          |
|-------:|--------------------|--------------------------------------|
| POST   | `/detector/start`  | Start the detector with a config.    |

### 🧠 Ask (RAG + NLQ over packets)

| Method | Endpoint | Description                                 |
|-------:|----------|---------------------------------------------|
| POST   | `/ask`   | Natural-language Q&A over packets and KB.   |

### 🗺️ Map & RSSI Utilities

| Method | Endpoint               | Description                                      |
|-------:|------------------------|--------------------------------------------------|
| GET    | `/map/ap-locations`    | Retrieve AP locations for map rendering.         |
| GET    | `/map/source-rssi`     | Average RSSI per BSSID for a given source MAC.   |
| POST   | `/map/estimate-origin` | Estimate rough origin of a source using RSSI.    |

### 🧾 Reports

| Method | Endpoint            | Description                              |
|-------:|---------------------|------------------------------------------|
| GET    | `/reports/summary`  | JSON summary of detected attacks.        |
| POST   | `/reports/export`   | Generate and download a PDF report.      |
| POST   | `/reports/email`    | Stub endpoint for email-based reporting. |
