# 🔒 Wi-Fi Intrusion Prevention System (IPS)

**HawkShield – Wi-Fi Intrusion Prevention System (IPS)** is a real-time AI-powered platform designed to detect, classify, and **prevent** malicious Wi-Fi activities before they disrupt the network.  
Built for **edge deployment on Raspberry Pi 5**, it leverages **machine learning**, a **RAG system**, and an **AI assistant** to secure networks in real time.

---

## 🌟 Features

- 📡 **Packet Capture**: Sniffs live 802.11 packets in monitor mode.  
- 🔍 **Feature Extraction**: Extracts 28+ features per packet for ML processing.  
- 🤖 **Attack Detection**: LightGBM-based classifier to detect normal vs attack traffic.  
- 🛡️ **Attack Type Classification**: Multi-class classification (Deauth, Evil Twin, RogueAP, KRACK, ReAssoc, SSDP/DoS).  
- ⚡ **Real-Time Prevention**: Disconnects malicious sources after threshold detection.  
- 🧠 **RAG System & AI Assistant**: Provides interactive Q&A, summarizes logs, and explains attack patterns.  
- 📊 **Dashboard & Reports**: JSON + PDF export for attack statistics.  
- 🗺️ **Map Utilities**: AP location mapping and rough origin estimation.  

---

## 🚀 Tech Stack

- **FastAPI** – REST API framework  
- **Streamlit** – Interactive dashboard  
- **LightGBM / scikit-learn** – ML-based attack classification  
- **Pyshark, Scapy, Tshark** – Live packet capture & analysis  
- **SQLite / PostgreSQL** – Storage for packets & stats  
- **Matplotlib / Seaborn** – Data visualization  
- **ReportLab** – PDF reporting  
- **Vector DB (FAISS/Qdrant)** – RAG-based attack knowledge  
- **Raspberry Pi 5** – Edge hardware deployment  

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

---

### 🛠️ Detector Control

| Method | Endpoint           | Description                          |
|-------:|--------------------|--------------------------------------|
| POST   | `/detector/start`  | Start the detector with a config.    |

---

### 🧠 Ask (RAG + NLQ over packets)

| Method | Endpoint | Description                                 |
|-------:|----------|---------------------------------------------|
| POST   | `/ask`   | Natural-language Q&A over packets and KB.   |

---

### 🗺️ Map & RSSI Utilities

| Method | Endpoint               | Description                                      |
|-------:|------------------------|--------------------------------------------------|
| GET    | `/map/ap-locations`    | Retrieve AP locations for map rendering.         |
| GET    | `/map/source-rssi`     | Average RSSI per BSSID for a given source MAC.   |
| POST   | `/map/estimate-origin` | Estimate rough origin of a source using RSSI.    |

---

### 🧾 Reports

| Method | Endpoint            | Description                              |
|-------:|---------------------|------------------------------------------|
| GET    | `/reports/summary`  | JSON summary of detected attacks.        |
| POST   | `/reports/export`   | Generate and download a PDF report.      |
| POST   | `/reports/email`    | Stub endpoint for email-based reporting. |

---

## 📥 Setup & Installation

### 1. Clone the Repo
```bash
git clone https://github.com/yourusername/HawkShield-IPS.git
cd HawkShield-IPS
````

### 2. Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the API

```bash
uvicorn main:app --reload
```

> Swagger UI available at: `http://127.0.0.1:8000/docs`

---



---

## 📁 Folder Structure

```

HawkShield-IPS/
├── AI\_models/           # Trained ML models (LightGBM, scikit-learn, etc.)
├── backend/             # FastAPI backend (routers, services, DB, utils)
├── Data/                # Raw & processed datasets
├── frontend/            # Streamlit or web dashboard code
├── Notebooks/           # Jupyter/Colab notebooks for experiments & EDA
├── main.py              # API entry point
├── requirements.txt     # Python dependencies
├── pyproject.toml       # Project configuration (optional)
├── .gitignore           # Git ignore rules
├── .python-version      # Python version pin
└── README.md            # Project documentation

```


---


## 🧑‍💻 Contributing

Contributions are welcome! Fork the repo and open a pull request.

---

## 📜 License

Copyright (c) 2025 \[Your Name]

All rights reserved. Unauthorized copying, modification, or distribution is prohibited.

---

## 📬 Contact

Developed by [Your Team / Name](https://www.linkedin.com/in/yourprofile)
📧 [your\_email@example.com](mailto:your_email@example.com)

---

## 🌍 Future Plans

* 📲 Mobile dashboard integration
* 🔔 Real-time alerting (email, webhooks)
* ☁️ Cloud sync for reports
* 🧩 Enterprise SIEM integration

```

---

Would you like me to also **add your team members section** (like in your infographic: Lena, Ghala, Mohammed, Yasser, Haya) under the Contact area?
```
