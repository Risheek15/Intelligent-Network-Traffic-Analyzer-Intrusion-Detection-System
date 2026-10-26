# Intelligent Network Traffic Analyzer & Intrusion Detection System (IDS)

**Computer Networks Semester Project — Risheek Teja (24BCE0669)**

A real-time hybrid Network Traffic Analyzer & Intrusion Detection System combining live packet sniffing with supervised machine learning and unsupervised anomaly detection, surfaced through a dual-dashboard web portal.

---

## 🌟 Key Highlights & Architecture

1. **Dual Dashboard Web Portal**:
   - **Network Traffic Analyzer (`/analyzer` / `/`)**: Real-time packet throughput (Packets & Bandwidth KB/s toggle), protocol distribution doughnut chart (TCP/UDP/ICMP), and a Live Network Flow Inspector terminal equipped with dual-handle range sliding bars (Lower & Upper limit filters for Packets, Bandwidth, and Socket Flows).
   - **Intrusion Detection System (`/ids`)**: Real-time threat classification table, live Isolation Forest dynamic sensitivity threshold badge, severity prioritization, and one-click SOC remediation playbooks with copyable Windows PowerShell firewall commands (`New-NetFirewallRule`).

2. **Hybrid Dual-Model Machine Learning Engine**:
   - **Supervised Classifier (Random Forest)**: Identifies known attack vectors (`port_scan`, `dos`, `brute_force`).
   - **Unsupervised Anomaly Detector (Isolation Forest)**: Continuously scores network behavior against learned normal baselines to catch novel zero-day anomalies and unknown traffic spikes.
   - **Adaptive Dynamic Feedback Loop**: Technician feedback (`True Positive` / `False Positive`) dynamically adjusts the Isolation Forest anomaly threshold in real time, making the detector self-tuning.

3. **Technician Authentication**:
   - Built-in session security with customizable technician registration and login.
   - Default credentials: `admin` / `admin123`.

---

## 📁 Project Structure

```text
network-ids/
├── requirements.txt              # Project dependencies
├── README.md                     # Comprehensive documentation
├── data/
│   └── sample_traffic.csv        # Labelled network flow training dataset
├── src/
│   ├── capture.py                # Scapy packet capture into rolling time-windows
│   ├── feature_extraction.py     # 12-dimensional statistical flow extraction & IP attribution
│   ├── database.py               # SQLite storage (windows, incidents, users, dynamic settings)
│   ├── detect.py                 # Real-time sniffer & dual-model ML detection pipeline
│   ├── app.py                    # Flask server, REST APIs, and technician session controller
│   └── models/
│       ├── train_models.py       # Training pipeline for Random Forest & Isolation Forest
│       ├── rf_model.pkl          # Trained Random Forest classifier
│       ├── iso_model.pkl         # Trained Isolation Forest anomaly detector
│       └── label_encoder.pkl     # Attack label encoder
├── templates/
│   ├── analyzer.html             # Network Traffic Analyzer UI & sliding filter toolbar
│   ├── ids.html                  # Intrusion Detection System incident & remediation dashboard
│   ├── login.html                # Technician authentication portal
│   └── register.html             # Technician registration portal
└── static/
    ├── style.css                 # Unified dark SOC theme & custom slider styling
    ├── analyzer.js               # Traffic chart renderers & dual-sliding filter logic
    ├── ids.js                    # Incident table manager & dynamic threshold updater
    └── chart.umd.min.js          # Chart.js local vendor library
```

---

## 🚀 Setup & Installation

### 1. Prerequisites
- Python 3.10+
- On Windows: Npcap installed with "WinPcap API-compatible mode" enabled.
- On Linux: `sudo apt-get install libpcap-dev`

### 2. Environment Setup
```bash
# Clone the repository
git clone https://github.com/Risheek15/Intelligent-Network-Traffic-Analyzer-Intrusion-Detection-System.git
cd Intelligent-Network-Traffic-Analyzer-Intrusion-Detection-System

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate            # Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Running the System

### Step 1: Start the Web Dashboard
```bash
python src/app.py
```
Open **http://127.0.0.1:5000** in your browser.
Log in using:
- **Technician ID:** `admin`
- **Password:** `admin123`

### Step 2: Start the Live Sniffer & ML Detection Loop
In an administrative terminal (with venv active):
```bash
# Windows (Wi-Fi or Ethernet adapter)
python src/detect.py --iface Wi-Fi --window 5

# Linux
sudo python src/detect.py --iface eth0 --window 5
```
Every 5 seconds, the engine aggregates raw network packets, extracts 12 statistical flow features, runs inference against both models, updates `traffic.db`, and broadcasts live alerts to the dashboard.

---

## 🛡️ Machine Learning Methodology

| Model | Technique | Target Threats | Evaluation Metric |
| :--- | :--- | :--- | :--- |
| **Random Forest** | Supervised Ensemble (200 Trees) | Port Scan, DoS, Brute Force | Accuracy, Precision/Recall |
| **Isolation Forest** | Unsupervised Isolation Trees | Zero-Day Outliers, High-Volume Bursts | Anomaly Score vs. Adaptive Threshold |

### Adaptive Self-Tuning Threshold
* Baseline default: `-0.080` (clamped between `[-0.20, -0.05]`).
* When a technician marks an anomaly as a **False Positive**, the system raises its threshold standard (making it more selective and reducing alert fatigue).
* Marking an event as a **True Positive** rewards detection sensitivity.
