import os, sys, time, json, pickle, csv, threading
from datetime import datetime
from collections import defaultdict

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

from scapy.all import sniff, rdpcap, IP, TCP, UDP, Raw

# =======================
# 1. Folder Initialization
# =======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LIB_DIR = os.path.join(BASE_DIR, "ML_LIBRARY")
OUT_DIR = os.path.join(BASE_DIR, "OUTPUTS")

os.makedirs(LIB_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)

# =======================
# 2. Normalize dataset name
# =======================
def normalize_name(path):
    name = os.path.basename(path)
    name = name.replace(".csv","").replace(".pcap","").replace(".pcapng","")
    name = name.replace(" ", "_").replace("-", "_")
    return name.upper()

# =======================
# 3. Get or create dataset folder (overwrite mode)
# =======================
def get_dataset_folder(name):
    folder = os.path.join(LIB_DIR, name)
    os.makedirs(folder, exist_ok=True)
    return folder

# =======================
# 4. Create output folder (auto-increment)
# =======================
def get_output_folder(name):
    base = os.path.join(OUT_DIR, name + "_OUTPUT")
    folder = base
    i = 2
    while os.path.exists(folder):
        folder = base + f"_{i}"
        i += 1
    os.makedirs(folder)
    return folder

# =======================
# 5. Save model objects
# =======================
def save_model_objects(folder, model, scaler, enc_proto, enc_state, features):
    with open(os.path.join(folder, "model.pkl"), "wb") as f:
        pickle.dump(model, f)
    with open(os.path.join(folder, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(folder, "enc_proto.pkl"), "wb") as f:
        pickle.dump(enc_proto, f)
    with open(os.path.join(folder, "enc_state.pkl"), "wb") as f:
        pickle.dump(enc_state, f)
    with open(os.path.join(folder, "metadata.json"), "w") as f:
        json.dump({"features": features}, f, indent=4)
# =======================
# 6. Load model objects
# =======================
def load_model_objects(folder):
    with open(os.path.join(folder, "model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(folder, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    with open(os.path.join(folder, "enc_proto.pkl"), "rb") as f:
        enc_proto = pickle.load(f)
    with open(os.path.join(folder, "enc_state.pkl"), "rb") as f:
        enc_state = pickle.load(f)
    with open(os.path.join(folder, "metadata.json"), "r") as f:
        meta = json.load(f)
    return model, scaler, enc_proto, enc_state, meta["features"]
# ------------------------------------------------------------
# 7. HYBRID FLOW EXTRACTION (Bidirectional, UNSW-Style)
# ------------------------------------------------------------
def extract_flow_features(packets):
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0

        # Build forward and reverse keys
        fwd_key = (src, dst, proto, sport, dport)
        rev_key = (dst, src, proto, dport, sport)

        # Decide direction
        if fwd_key in flows:
            key = fwd_key
            direction = "fwd"
        elif rev_key in flows:
            key = rev_key
            direction = "rev"
        else:
            key = fwd_key
            direction = "fwd"
            flows[key] = {
                "src": src, "dst": dst,
                "sport": sport, "dport": dport,
                "proto": proto,
                "spkts": 0, "dpkts": 0,
                "sbytes": 0, "dbytes": 0,
                "sttl": [], "dttl": [],
                "first_ts": pkt.time,
                "last_ts": pkt.time,
            }

        fl = flows[key]

        # Update timestamps
        fl["last_ts"] = pkt.time

        # Update directional metrics
        if direction == "fwd":
            fl["spkts"] += 1
            fl["sbytes"] += len(pkt)
            fl["sttl"].append(pkt[IP].ttl)
        else:
            fl["dpkts"] += 1
            fl["dbytes"] += len(pkt)
            fl["dttl"].append(pkt[IP].ttl)

    # Convert flows to rows
    rows = []
    for key, f in flows.items():
        duration = max(0.0001, f["last_ts"] - f["first_ts"])

        rows.append({
            "src": f["src"],
            "dst": f["dst"],
            "sport": f["sport"],
            "dport": f["dport"],
            "proto": f["proto"],
            "spkts": f["spkts"],
            "dpkts": f["dpkts"],
            "sbytes": f["sbytes"],
            "dbytes": f["dbytes"],
            "sttl": np.mean(f["sttl"]) if f["sttl"] else 64,
            "dttl": np.mean(f["dttl"]) if f["dttl"] else 64,
            "dur": duration,
        })

    return pd.DataFrame(rows)
# =======================
# 8 .CSV LOADER (Flow-level Dataset)
# =======================
def load_csv_dataset(path):
    df = pd.read_csv(path)
    
    # Select hybrid UNSW-like features
    cols = ["proto","sport","dport","spkts","dpkts","sbytes","dbytes","sttl","dttl","dur"]
    for c in cols:
        if c not in df.columns:
            df[c] = 0

    return df[cols]
# =======================
# 9. PCAP LOADER (Packet-Level → Hybrid Flow Extraction)
# =======================
def load_pcap_dataset(path):
    pkts = rdpcap(path)
    df = extract_flow_features(pkts)
    return df
# =======================
# 10. MODEL TRAINING (FIX-4 IMPROVED)
# =======================
def train_isolation_forest(df, dataset_name):
    df = df.fillna(0)

    # Encode protocol safely
    enc_proto = LabelEncoder()
    df["proto"] = enc_proto.fit_transform(df["proto"].astype(str))

    # Placeholder since UNSW uses "state"
    df["state"] = 0

    features = ["proto","sport","dport","spkts","dpkts","sbytes","dbytes","sttl","dttl","dur","state"]

    scaler = StandardScaler()
    X = scaler.fit_transform(df[features])

    # FIX-4: improved model = more stable, fewer false alarms
    model = IsolationForest(
        n_estimators=300,
        contamination="auto",      # adaptive contamination
        max_samples="auto",
        random_state=42,
        bootstrap=True,
        max_features=1.0,
        warm_start=True
    )

    model.fit(X)

    folder = get_dataset_folder(dataset_name)
    save_model_objects(folder, model, scaler, enc_proto, LabelEncoder(), features)

    print(f"\n[+] Model trained and saved in: {folder}")
    return folder
# =======================
# 11. TRAINING CONTROLLER
# =======================
def train_from_path(path):
    name = normalize_name(path)
    print(f"\n[+] Training model for dataset: {name}")

    if path.endswith(".csv"):
        df = load_csv_dataset(path)
    elif path.endswith(".pcap") or path.endswith(".pcapng"):
        df = load_pcap_dataset(path)
    else:
        print("Invalid file type. Use CSV or PCAP.")
        return

    folder = train_isolation_forest(df, name)
    print("\n[+] Training completed.\n")
    return folder
# ------------------------------------------------------------
# 12. LIVE CAPTURE + ML ANOMALY DETECTION
# ------------------------------------------------------------

live_packets = []

def live_sniffer(pkt):
    live_packets.append(pkt)

def capture_live(minutes):
    global live_packets
    live_packets = []
    sec = int(minutes * 60)
    print(f"\n[+] Capturing for {minutes} minute(s)... Press CTRL+C to stop.")
    sniff(timeout=sec, prn=live_sniffer)
    print(f"[+] Capture complete. {len(live_packets)} packets captured.")
    return live_packets
# =======================
# 13. Build Flows in Real-Time (Hybrid Method)
# =======================
def build_live_flows(pkts):
    return extract_flow_features(pkts)
# =======================
# 14. Predict Anomalies Using Trained Model (NUMERIC PROTO – SAFE & UNIVERSAL)
# =======================
def predict_live(df, model, scaler, enc_proto, enc_state, features):

    df = df.fillna(0)

    # ---- NUMERIC PROTOCOL HANDLING (NO LABEL ENCODING) ----
    # Keep protocol as raw numeric RFC 790 values
    try:
        df["proto"] = df["proto"].astype(int)
    except:
        df["proto"] = df["proto"].apply(lambda x: int(x) if str(x).isdigit() else 0)

    # ---- Placeholder for state (not used but required by model) ----
    df["state"] = 0

    # Ensure all required features exist
    for f in features:
        if f not in df.columns:
            df[f] = 0

    # Prepare ML features
    X = scaler.transform(df[features])

    preds = model.predict(X)
    scores = model.decision_function(X)

    df["anomaly"] = preds
    df["score"] = scores
    return df

# =======================
# 15. Save Detection Output (UNIVERSAL SAFE)
# =======================
def save_live_output(df, dataset_name):
    folder = get_output_folder(dataset_name)

    # Save full results
    df.to_csv(os.path.join(folder, "results.csv"), index=False)

    # Save anomalies only
    anomalies = df[df["anomaly"] == -1]
    anomalies.to_csv(os.path.join(folder, "anomalies.csv"), index=False)

    # Alerts log (SAFE for all dataset types)
    with open(os.path.join(folder, "alerts.log"), "w") as f:
        for _, r in anomalies.iterrows():
            src = r.get("src", "N/A")
            dst = r.get("dst", "N/A")
            proto = r.get("proto", "N/A")
            score = r.get("score", 0)

            f.write(
                f"[ALERT] src={src} dst={dst} proto={proto} score={score:.4f}\n"
            )

    # Plot anomaly scores
    plt.figure(figsize=(10, 4))

    normals = df[df["anomaly"] == 1]
    anoms = df[df["anomaly"] == -1]

    plt.scatter(normals.index, normals["score"], s=6, color="blue", label="Normal")
    plt.scatter(anoms.index, anoms["score"], s=8, color="red", label="Anomaly")

    plt.title("Anomaly Detection Score Plot")
    plt.xlabel("Flow Index")
    plt.ylabel("Anomaly Score")
    plt.legend()
    plt.tight_layout()

    plt.savefig(os.path.join(folder, "anomaly_graph.png"))
    plt.close()

    print(f"\n[+] Detection outputs saved in:\n{folder}")
# =======================
# 16. Main Live Detection Pipeline
# =======================
def run_live_detection():
    ds_list = os.listdir(LIB_DIR)
    if not ds_list:
        print("\n[!] No trained models found. Train a model first.\n")
        return

    print("\nAvailable trained datasets:")
    for i, ds in enumerate(ds_list, start=1):
        print(f"  {i}. {ds}")

    try:
        choice = int(input("\nSelect which dataset model to use: "))
        dataset_name = ds_list[choice - 1]
    except:
        print("[!] Invalid selection.")
        return

    model_folder = os.path.join(LIB_DIR, dataset_name)
    model, scaler, enc_proto, enc_state, features = load_model_objects(model_folder)

    print("""
Select detection mode:
  1. Live Network Capture
  2. Existing PCAP File
  3. Existing CSV File
""")

    mode = input("Enter your choice (1–3): ").strip()

    # -------------------------------
    # MODE 1 — LIVE CAPTURE
    # -------------------------------
    if mode == "1":
        print("\nEnter live capture duration (minutes, allowed 1–10):")
        try:
            mins = float(input("> ").strip())
        except:
            print("[!] Invalid input.")
            return

        if mins < 1 or mins > 10:
            print("[!] Duration must be between 1 and 10 minutes.")
            return

        pkts = capture_live(mins)
        df = build_live_flows(pkts)

        if df.empty:
            print("[!] No flows extracted.")
            return

        df_pred = predict_live(df, model, scaler, enc_proto, enc_state, features)
        save_live_output(df_pred, dataset_name)

        print("\n[+] Live anomaly detection complete.\n")
    # -------------------------------
    # MODE 2 or 3 — EXISTING FILE
    # -------------------------------
    elif mode == "2" or mode == "3":
        path = input("\nEnter PCAP or CSV path: ").strip()

        if not os.path.exists(path):
            print("[!] File does not exist.")
            return

        if path.endswith(".csv"):
            df = load_csv_dataset(path)
        elif path.endswith(".pcap") or path.endswith(".pcapng"):
            df = load_pcap_dataset(path)
        else:
            print("[!] Unsupported file type.")
            return

        if df.empty:
            print("[!] No flows extracted.")
            return

        df_pred = predict_live(df, model, scaler, enc_proto, enc_state, features)
        save_live_output(df_pred, dataset_name)

        print("\n[+] Detection on existing file completed.\n")

    else:
        print("[!] Invalid option.")
        return

# ------------------------------------------------------------
# MAIN MENU SYSTEM
# ------------------------------------------------------------

def main_menu():
    while True:
        print("""
==================================================
              ANOMALY DETECTION SYSTEM
==================================================

Please select an operation:

  1. Load Dataset / Select Input File (Train Model)
  2. Initiate Live Anomaly Detection
  3. Terminate Application

--------------------------------------------------
""")

        choice = input("Enter your selection (1–3): ").strip()

        if choice == "1":
            path = input("\nEnter dataset path (CSV or PCAP): ").strip()
            if not os.path.exists(path):
                print("[!] File does not exist.\n")
                continue
            train_from_path(path)

        elif choice == "2":
            run_live_detection()

        elif choice == "3":
            print("\n[+] Terminating application.\n")
            sys.exit(0)

        else:
            print("\n[!] Invalid selection. Try again.\n")


# ------------------------------------------------------------
# PROGRAM ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.\n")
