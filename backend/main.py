from fastapi import FastAPI
import joblib
import pandas as pd
import time
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP

app = FastAPI(title="IDS")

# modelo
model = joblib.load("modelo_xgboost.pkl")
le_attack = joblib.load("label_encoder.pkl")
features = joblib.load("features.pkl")
le_dict = joblib.load("encoders.pkl")
scaler = joblib.load("scaler.pkl")

# variables globales
flows = {}
packets_buffer = []
alerts = []

FLOW_TIMEOUT = 5  # segundos

# flujo
def get_flow_id(pkt):
    if IP in pkt:
        return (
            pkt[IP].src,
            pkt[IP].dst,
            getattr(pkt, "sport", 0),
            getattr(pkt, "dport", 0),
            pkt[IP].proto
        )
    return None

# extraer informacion del paquete
def extract_packet_info(pkt):

    data = {
        "Length": len(pkt),
        "time": time.time()
    }

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

    else:
        data["Protocol"] = "Other"

    return data

# actualizar flujo
def update_flow(flow_id, pkt_info):

    if flow_id not in flows:
        flows[flow_id] = {
            "start_time": pkt_info["time"],
            "last_time": pkt_info["time"],
            "bytes": 0,
            "packets": 0,
            "data": pkt_info
        }

    flow = flows[flow_id]

    flow["bytes"] += pkt_info["Length"]
    flow["packets"] += 1
    flow["last_time"] = pkt_info["time"]

    flow["data"].update(pkt_info)

# flujo -> caracteristicas
def flow_to_features(flow):

    data = flow["data"].copy()

    data["Duration"] = flow["last_time"] - flow["start_time"]
    data["Length"] = flow["bytes"]

    return data

# preprocesamiento
def preprocess(df):

    df = df.copy()

    drop_cols = ["Source", "Destination", "Info", "Label", "Attack Category"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    # TCP FLAGS
    tcp_flags = ['TCP Syn', 'TCP ACK', 'TCP FIN', 'TCP RST', 'TCP PSH', 'TCP URG']

    for col in tcp_flags:
        if col not in df.columns:
            df[col] = 0

    # NUMÉRICAS
    num_cols = ['Duration', 'Length', 'TCP Window Size', 'TCP Sequence Number']

    for col in num_cols:
        if col not in df.columns:
            df[col] = 0

    # LABEL ENCODING
    for col, le in le_dict.items():

        if col not in df.columns:
            df[col] = -1
        else:
            df[col] = df[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )

    # ESCALADO
    df[num_cols] = scaler.transform(df[num_cols])

    # FEATURES EXACTAS
    df = df.reindex(columns=features, fill_value=0)

    return df

# SEVERIDAD
def severity_map(pred):

    return {
        "Normal": "🟢 Bajo",
        "Port scan": "🟡 Medio",
        "Vulnerability scan": "🟠 Alto",
        "DoS": "🔴 Crítico"
    }.get(pred, "⚪ Desconocido")

# PACKET HANDLER
def packet_handler(pkt):

    global packets_buffer, alerts

    flow_id = get_flow_id(pkt)

    if not flow_id:
        return

    pkt_info = extract_packet_info(pkt)
    update_flow(flow_id, pkt_info)

    now = time.time()

    expired = [
        f for f, v in flows.items()
        if now - v["last_time"] > FLOW_TIMEOUT
    ]

    for fid in expired:

        flow = flows.pop(fid)

        try:

            feat = flow_to_features(flow)
            X = preprocess(pd.DataFrame([feat]))

            pred = le_attack.inverse_transform(
                model.predict(X)
            )[0]

            record = {
                "Timestamp": time.strftime("%H:%M:%S"),
                "Source IP": fid[0],
                "Destination IP": fid[1],
                "Protocol": feat.get("Protocol"),
                "Packets": flow["packets"],
                "Bytes": feat.get("Length"),
                "Prediction": pred,
                "Severity": severity_map(pred)
            }

            packets_buffer.append(record)
            alerts.append(record) if pred != "Normal" else None

        except Exception as e:
            print("Error:", e)

# SNIFFER THREAD
def start_sniffing():
    sniff(prn=packet_handler, store=False)

@app.on_event("startup")
def startup_event():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()

# API ENDPOINTS
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