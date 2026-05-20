from fastapi import FastAPI
import joblib
import pandas as pd
import time
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP

app = FastAPI()

# -------------------------------
# MODELO
# -------------------------------
model = joblib.load("modelo_xgboost.pkl")
le_attack = joblib.load("label_encoder.pkl")
features = joblib.load("features.pkl")
le_dict = joblib.load("encoders.pkl")
scaler = joblib.load("scaler.pkl")

# -------------------------------
# GLOBALS
# -------------------------------
flows = {}
packets_buffer = []
alerts = []

FLOW_TIMEOUT = 5

# -------------------------------
# FLOW ID
# -------------------------------
def get_flow_id(pkt):
    if IP in pkt:
        return (
            pkt[IP].src,
            pkt[IP].dst,
            pkt.sport if hasattr(pkt, "sport") else 0,
            pkt.dport if hasattr(pkt, "dport") else 0,
            pkt[IP].proto
        )
    return None

# -------------------------------
# PACKET INFO
# -------------------------------
def extract_packet_info(pkt):
    data = {"Length": len(pkt), "time": time.time()}

    if TCP in pkt:
        flags = pkt[TCP].flags
        data.update({
            "Protocol": "TCP",
            "TCP Syn": int(flags.S),
            "TCP ACK": int(flags.A),
            "TCP FIN": int(flags.F),
            "TCP RST": int(flags.R),
            "TCP PSH": int(flags.P),
            "TCP URG": int(flags.U),
            "TCP Window Size": pkt[TCP].window,
            "TCP Sequence Number": pkt[TCP].seq
        })

    elif UDP in pkt:
        data["Protocol"] = "UDP"

    elif ICMP in pkt:
        data["Protocol"] = "ICMP"
        data["ICMP Type"] = pkt[ICMP].type

    return data

# -------------------------------
# FLOW UPDATE
# -------------------------------
def update_flow(flow_id, pkt_info):
    if flow_id not in flows:
        flows[flow_id] = {
            "start_time": pkt_info["time"],
            "last_time": pkt_info["time"],
            "bytes": 0,
            "data": pkt_info
        }

    flow = flows[flow_id]
    flow["bytes"] += pkt_info["Length"]
    flow["last_time"] = pkt_info["time"]
    flow["data"].update(pkt_info)

# -------------------------------
# FLOW FEATURES
# -------------------------------
def flow_to_features(flow):
    data = flow["data"].copy()
    data["Duration"] = flow["last_time"] - flow["start_time"]
    data["Length"] = flow["bytes"]
    return data

# -------------------------------
# PREPROCESS
# -------------------------------
def preprocess(df):
    df = df.copy()

    drop_cols = ["Source", "Destination", "Info", "Label", "Attack Category"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    tcp_flags = ['TCP Syn','TCP ACK','TCP FIN','TCP RST','TCP PSH','TCP URG']
    for c in tcp_flags:
        if c not in df:
            df[c] = 0

    for col, le in le_dict.items():
        df[col] = df[col].astype(str).apply(
            lambda x: le.transform([x])[0] if x in le.classes_ else -1
        ) if col in df else -1

    num_cols = ['Duration','Length','TCP Window Size','TCP Sequence Number']
    for c in num_cols:
        if c not in df:
            df[c] = 0

    df[num_cols] = scaler.transform(df[num_cols])

    return df.reindex(columns=features, fill_value=0)

# -------------------------------
# SEVERIDAD (IMPORTANTE PARA TESIS)
# -------------------------------
def severity_map(pred):
    return {
        "Normal": "🟢 Bajo",
        "Port Scan": "🟡 Medio",
        "Vulnerability Scan": "🟠 Alto",
        "DoS": "🔴 Crítico"
    }.get(pred, "⚪ Desconocido")

# -------------------------------
# PACKET HANDLER
# -------------------------------
def packet_handler(pkt):
    global packets_buffer, alerts

    flow_id = get_flow_id(pkt)
    if not flow_id:
        return

    pkt_info = extract_packet_info(pkt)
    update_flow(flow_id, pkt_info)

    now = time.time()
    expired = [f for f,v in flows.items() if now - v["last_time"] > FLOW_TIMEOUT]

    for fid in expired:
        flow = flows.pop(fid)

        try:
            feat = flow_to_features(flow)
            X = preprocess(pd.DataFrame([feat]))

            pred = le_attack.inverse_transform(model.predict(X))[0]
            severity = severity_map(pred)

            record = {
                "Timestamp": time.strftime("%H:%M:%S"),
                "Source IP": fid[0],
                "Destination IP": fid[1],
                "Protocol": feat.get("Protocol"),
                "Bytes": feat.get("Length"),
                "Prediction": pred,
                "Severity": severity
            }

            packets_buffer.append(record)

            if pred != "Normal":
                alerts.append(record)

        except Exception as e:
            print("Error:", e)

# -------------------------------
# SNIFFER
# -------------------------------
def start_sniffing():
    sniff(prn=packet_handler, store=False)

@app.on_event("startup")
def startup():
    t = threading.Thread(target=start_sniffing)
    t.daemon = True
    t.start()

# -------------------------------
# API
# -------------------------------
@app.get("/metrics")
def metrics():
    return {
        "total_packets": len(packets_buffer),
        "total_alerts": len(alerts)
    }

@app.get("/packets")
def packets():
    return packets_buffer[-50:]

@app.get("/alerts")
def alerts_api():
    return alerts[-50:]