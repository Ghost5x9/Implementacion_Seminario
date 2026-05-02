from fastapi import FastAPI
import joblib
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from collections import defaultdict

app = FastAPI()

# -------------------------------
# CARGAR MODELO
# -------------------------------
model = joblib.load("modelo_xgboost.pkl")
le_attack = joblib.load("label_encoder.pkl")
features = joblib.load("features.pkl")
le_dict = joblib.load("encoders.pkl")
scaler = joblib.load("scaler.pkl")

# -------------------------------
# VARIABLES GLOBALES
# -------------------------------
flows = {}
packets_buffer = []
alerts = []

FLOW_TIMEOUT = 5  # segundos

# -------------------------------
# EXTRAER FEATURES BASE
# -------------------------------
def get_flow_id(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto

        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0

        return (src, dst, sport, dport, proto)
    return None


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


# -------------------------------
# ACTUALIZAR FLOW
# -------------------------------
def update_flow(flow_id, pkt_info):
    if flow_id not in flows:
        flows[flow_id] = {
            "start_time": pkt_info["time"],
            "last_time": pkt_info["time"],
            "packets": 0,
            "bytes": 0,
            "data": pkt_info
        }

    flow = flows[flow_id]
    flow["packets"] += 1
    flow["bytes"] += pkt_info["Length"]
    flow["last_time"] = pkt_info["time"]

    # guardar última info TCP
    flow["data"].update(pkt_info)


# -------------------------------
# CONVERTIR FLOW → FEATURES
# -------------------------------
def flow_to_features(flow):
    duration = flow["last_time"] - flow["start_time"]

    data = flow["data"].copy()

    data["Duration"] = duration
    data["Length"] = flow["bytes"]

    return data


# -------------------------------
# PREPROCESAMIENTO (igual entrenamiento)
# -------------------------------
def preprocess(df):
    df = df.copy()

    drop_cols = ["Source", "Destination", "Info", "Label", "Attack Category"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    tcp_flags = ['TCP Syn', 'TCP ACK', 'TCP FIN', 'TCP RST', 'TCP PSH', 'TCP URG']

    for col in tcp_flags:
        if col not in df.columns:
            df[col] = 0

    for col, le in le_dict.items():
        if col in df.columns:
            df[col] = df[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )
        else:
            df[col] = -1

    num_cols = ['Duration', 'Length', 'TCP Window Size', 'TCP Sequence Number']

    for col in num_cols:
        if col not in df.columns:
            df[col] = 0

    df[num_cols] = scaler.transform(df[num_cols])

    df = df.reindex(columns=features, fill_value=0)

    return df


# -------------------------------
# PROCESAR PAQUETE
# -------------------------------
def packet_handler(pkt):
    global packets_buffer, alerts

    flow_id = get_flow_id(pkt)
    if flow_id is None:
        return

    pkt_info = extract_packet_info(pkt)
    update_flow(flow_id, pkt_info)

    # revisar timeout de flows
    now = time.time()
    expired = []

    for fid, flow in flows.items():
        if now - flow["last_time"] > FLOW_TIMEOUT:
            expired.append(fid)

    for fid in expired:
        flow = flows.pop(fid)

        try:
            feat = flow_to_features(flow)
            df = pd.DataFrame([feat])

            X = preprocess(df)

            pred_encoded = model.predict(X)
            pred = le_attack.inverse_transform(pred_encoded)[0]

            packets_buffer.append({
                "Protocol": feat.get("Protocol"),
                "Bytes": feat.get("Length"),
                "Prediccion": pred
            })

            if pred != "Normal":
                alerts.append({
                    "Tipo": pred,
                    "Hora": time.strftime("%H:%M:%S"),
                    "Riesgo": "Alto"
                })

        except Exception as e:
            print("Error:", e)


# -------------------------------
# INICIAR SNIFFER
# -------------------------------
def start_sniffing():
    sniff(prn=packet_handler, store=False)


@app.on_event("startup")
def startup_event():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()


# -------------------------------
# ENDPOINTS
# -------------------------------
@app.get("/metrics")
def get_metrics():
    return {
        "total_packets": len(packets_buffer),
        "total_alerts": len(alerts)
    }


@app.get("/packets")
def get_packets():
    return packets_buffer[-50:]


@app.get("/alerts")
def get_alerts():
    return alerts[-50:]