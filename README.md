# 🧠 ML-Based Anomaly Detection IDS

## 🔍 Introduction

Intrusion Detection Systems (IDS) are a cornerstone of modern network security, providing real-time visibility into malicious or anomalous traffic. This project implements a **Machine Learning-Based Anomaly Detection IDS** using Python leveraging **Isolation Forest**, a powerful unsupervised ML algorithm, to identify abnormal network behavior without requiring labeled attack data.

Unlike signature-based IDS tools, this system learns the baseline of "normal" network traffic and flags statistical deviations making it effective against **zero-day threats, novel attack patterns, and behavioral anomalies** that rule-based systems would miss.

The system supports **CSV datasets** (e.g., UNSW-NB15, CIC-IDS), **PCAP/PCAPng files**, and **live packet capture** covering all major use cases from academic research to real-world deployment.

---

## 🤖 ML Engine Overview

**Isolation Forest** is the core algorithm behind this IDS. It works by isolating observations using random decision trees anomalies, being rare and different, are isolated faster and receive lower anomaly scores.

### Why Isolation Forest?

| Feature | Benefit |
|---|---|
| **Unsupervised Learning** | No labeled attack data required for training |
| **Zero-Day Detection** | Flags unknown threats based on behavioral deviation |
| **Scalable** | Handles large datasets efficiently with `n_estimators=300` |
| **Low False Positive Rate** | Uses adaptive `contamination="auto"` for calibrated thresholds |
| **Persistent Models** | Trained models are saved and reusable across sessions |

---

## 🔑 Key Components

| Component | Description |
|---|---|
| **Isolation Forest Model** | Core ML algorithm for unsupervised anomaly detection |
| **Hybrid Flow Extractor** | Converts raw packets into bidirectional UNSW-style network flows |
| **StandardScaler** | Normalizes feature values for consistent ML input |
| **LabelEncoder** | Encodes categorical protocol fields into numeric representations |
| **Scapy Integration** | Enables real-time packet sniffing and PCAP file parsing |
| **ML_LIBRARY/** | Persists trained models, scalers, and encoders per dataset |
| **OUTPUTS/** | Stores detection results, anomaly CSVs, alerts log, and score plots |

---

## 📐 Flow Features Extracted (UNSW-NB15 Style)

| Feature | Description |
|---|---|
| `proto` | Network protocol (TCP, UDP, ICMP, etc.) |
| `sport` | Source port number |
| `dport` | Destination port number |
| `spkts` | Number of packets sent by source |
| `dpkts` | Number of packets sent by destination |
| `sbytes` | Total bytes sent by source |
| `dbytes` | Total bytes sent by destination |
| `sttl` | Mean TTL value of source packets |
| `dttl` | Mean TTL value of destination packets |
| `dur` | Flow duration in seconds |

---

## 🧰 Project Workflow

1. **Select Input** — Choose a CSV dataset, PCAP file, or live network interface
2. **Flow Extraction** — Raw packets are aggregated into bidirectional network flows
3. **Preprocessing** — Features are encoded and normalized via `StandardScaler`
4. **Model Training** — Isolation Forest is fitted and persisted to `ML_LIBRARY/`
5. **Detection** — New traffic is scored; anomalies flagged with `prediction = -1`
6. **Output Generation** — Results saved as CSV, alerts log, and anomaly score plot

---

## 🖥️ System Architecture

```
IDS.py
│
├── ML_LIBRARY/
│   └── <DATASET_NAME>/
│       ├── model.pkl          ← Trained Isolation Forest
│       ├── scaler.pkl         ← StandardScaler
│       ├── enc_proto.pkl      ← Protocol LabelEncoder
│       ├── enc_state.pkl      ← State LabelEncoder (placeholder)
│       └── metadata.json      ← Feature list
│
└── OUTPUTS/
    └── <DATASET_NAME>_OUTPUT/
        ├── results.csv        ← All flows with anomaly labels and scores
        ├── anomalies.csv      ← Flagged anomalous flows only
        ├── alerts.log         ← Human-readable alert entries
        └── anomaly_graph.png  ← Anomaly score scatter plot
```

---

## ⚙️ Installation & Requirements

### Prerequisites

```bash
pip install numpy pandas scikit-learn matplotlib scapy
```

### Run the IDS

```bash
python IDS.py
```

---

## 🧭 Main Menu

```
==================================================
              ANOMALY DETECTION SYSTEM
==================================================

  1. Load Dataset / Select Input File (Train Model)
  2. Initiate Live Anomaly Detection
  3. Terminate Application
```

---

## 📡 Detection Modes

### 🔹 Mode 1 — Train on Dataset (CSV or PCAP)
Provide a network flow CSV (e.g., UNSW-NB15) or a PCAP capture file.  
The model learns what "normal" looks like and saves itself to `ML_LIBRARY/`.

### 🔹 Mode 2 — Live Network Capture
Sniffs live traffic on the host interface for 1–10 minutes.  
Flows are extracted in real time and passed through the trained model for anomaly scoring.

### 🔹 Mode 3 — Analyze Existing PCAP / CSV File
Loads a previously captured PCAP or flow CSV and runs it through a trained model — no live capture needed.

---

## 🚨 Sample Alert Output

```
[ALERT] src=192.168.1.105 dst=10.0.0.1 proto=6 score=-0.3412
[ALERT] src=172.16.0.23  dst=8.8.8.8   proto=17 score=-0.5871
[ALERT] src=192.168.1.200 dst=10.0.0.1 proto=1  score=-0.4103
```

Each alert includes the **source IP**, **destination IP**, **protocol number**, and the **raw anomaly score** — lower scores indicate stronger anomaly confidence.

---

## 📊 Anomaly Score Plot

After each detection run, a scatter plot (`anomaly_graph.png`) is saved showing:

- 🔵 **Blue points** — Normal flows
- 🔴 **Red points** — Detected anomalies

This provides a quick visual summary of traffic behavior across the analyzed session.

---

## 🏢 Practical Deployment Use Cases

### 🔹 1. Security Research & Dataset Analysis
Train the model on benchmark datasets like **UNSW-NB15** or **CIC-IDS2017** and evaluate detection performance against known attack traffic — ideal for academic and research environments.

### 🔹 2. Enterprise Network Monitoring
Deploy on a dedicated monitoring node with periodic PCAP ingestion to analyze internal traffic segments for behavioral anomalies — without needing a signature database.

### 🔹 3. Incident Response & Forensics
Feed captured PCAP evidence from an incident into the trained model to retrospectively identify which flows were anomalous — supporting forensic triage and post-mortem analysis.

### 🔹 4. Edge / IoT Security
Train on baseline IoT device traffic and detect deviations that may indicate compromise, lateral movement, or command-and-control communication.

---

## 🧠 Skills Demonstrated

| Category | Skills Developed |
|---|---|
| **Machine Learning** | Unsupervised anomaly detection with Isolation Forest |
| **Network Security** | Packet analysis, flow extraction, IDS architecture |
| **Data Engineering** | Feature engineering from raw PCAP and CSV datasets |
| **Python Development** | Modular scripting, file I/O, model persistence with `pickle` |
| **Network Programming** | Live packet sniffing with Scapy, PCAP parsing |
| **Data Visualization** | Anomaly score plotting with Matplotlib |

---

## 🏁 Conclusion

This project demonstrates how **unsupervised machine learning** can be applied to network security to detect anomalous traffic without prior knowledge of specific attack signatures. By combining **Scapy-based packet capture**, **hybrid bidirectional flow extraction**, and **Isolation Forest anomaly scoring**, the system delivers a flexible and extensible IDS capable of operating on real traffic, benchmark datasets, or pre-recorded captures.

---

## 👨‍💻 Built By

**Umar Ahamed**  
Cybersecurity Student • Sri Lanka  
Passionate about **network defense, machine learning security**, and **ethical hacking.**

⭐ Connect via GitHub: [User-Umar-Ahamed](https://github.com/User-Umar-Ahamed)
