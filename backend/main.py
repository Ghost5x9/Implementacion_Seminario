from fastapi import FastAPI
import joblib
import pandas as pd
import time
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS

app = FastAPI(title="IDS")

# ==================================================
# MODELOS
# ==================================================

model = joblib.load("modelo_xgboost.pkl")
le_attack = joblib.load("label_encoder.pkl")
features = joblib.load("features.pkl")
le_dict = joblib.load("encoders.pkl")
scaler = joblib.load("scaler.pkl")

# ==================================================
# VARIABLES GLOBALES
# ==================================================

flows = {}
packets_buffer = []
alerts = []

FLOW_TIMEOUT = 15

# ==================================================
# FLOW ID
# ==================================================

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


# ==================================================
# EXTRACCIÓN DE CARACTERÍSTICAS
# ==================================================

def extract_packet_info(pkt):

    data = {
        "Length": len(pkt),
        "time": time.time(),

        "TCP Syn": 0,
        "TCP ACK": 0,
        "TCP FIN": 0,
        "TCP RST": 0,
        "TCP PSH": 0,
        "TCP URG": 0,

        "TCP Window Size": 0,
        "TCP Sequence Number": 0,

        "ICMP Type": 0
    }

    # DNS
    if DNS in pkt:
        data["Protocol"] = "DNS"

    # TCP
    elif TCP in pkt:

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

    # UDP
    elif UDP in pkt:
        data["Protocol"] = "UDP"

    # ICMP
    elif ICMP in pkt:

        data["Protocol"] = "ICMP"

        try:
            data["ICMP Type"] = int(pkt[ICMP].type)
        except:
            data["ICMP Type"] = 0

    else:

        # importante:
        # si tu dataset no tiene "Other"
        # mejor mapearlo a UDP

        data["Protocol"] = "UDP"

    return data


# ==================================================
# ACTUALIZAR FLUJO
# ==================================================

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


# ==================================================
# FLOW → FEATURES
# ==================================================

def flow_to_features(flow):

    data = flow["data"].copy()

    data["Duration"] = (
        flow["last_time"] - flow["start_time"]
    )

    data["Length"] = flow["bytes"]

    return data


# ==================================================
# PREPROCESAMIENTO
# ==================================================

def preprocess(df):
    df = df.copy()

    # Columnas numéricas
    num_cols = ['Duration', 'Length', 'TCP Window Size', 'TCP Sequence Number', 'ICMP Type']

    # Columnas TCP flags
    tcp_flags = ['TCP Syn', 'TCP ACK', 'TCP FIN', 'TCP RST', 'TCP PSH', 'TCP URG']

    # Columnas categóricas
    cat_cols = ['Protocol']

    # -------------------------
    # Inicializar flags TCP
    # -------------------------
    for col in tcp_flags:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)

    # -------------------------
    # Inicializar numéricas
    # -------------------------
    for col in num_cols:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    # -------------------------
    # Protocol
    # -------------------------
    if 'Protocol' not in df.columns:
        df['Protocol'] = 'UDP'
    df['Protocol'] = df['Protocol'].astype(str).apply(
        lambda x: le_dict['Protocol'].transform([x])[0] if x in le_dict['Protocol'].classes_ else le_dict['Protocol'].transform(['UDP'])[0]
    )

    # -------------------------
    # Escalar numéricas
    # -------------------------
    df[num_cols] = scaler.transform(df[num_cols])

    # -------------------------
    # Reordenar columnas al orden original
    # -------------------------
    df = df.reindex(columns=features, fill_value=0)

    return df


# ==================================================
# SEVERIDAD
# ==================================================

def severity_map(pred):

    return {
        "Normal": "🟢 Bajo",
        "Port scan": "🟡 Medio",
        "Vulnerability scan": "🟠 Alto",
        "DoS": "🔴 Crítico"
    }.get(pred, "⚪ Desconocido")


# ==================================================
# HANDLER
# ==================================================

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

            print("\n======================")
            print("FEATURES ENVIADAS AL MODELO")
            print(X.head())

            print("\nPROBABILIDADES")
            print(model.predict_proba(X))

            # =====================================
            # PREDICCIÓN CON UMBRAL DE CONFIANZA
            # =====================================

            probs = model.predict_proba(X)[0]

            max_idx = probs.argmax()
            max_prob = float(probs[max_idx])

            pred = le_attack.classes_[max_idx]

            print("CLASES:", le_attack.classes_)
            print("PROBABILIDADES:", probs)
            print("CONFIANZA:", round(max_prob * 100, 2), "%")

            # Umbral de confianza
            CONFIDENCE_THRESHOLD = 0.7

            if pred != "Normal" and max_prob < CONFIDENCE_THRESHOLD:
                pred = "Normal"

            print("PREDICCIÓN FINAL:", pred)
            print("======================\n")

            record = {
                "Timestamp": time.strftime("%H:%M:%S"),
                "Source IP": fid[0],
                "Destination IP": fid[1],
                "Protocol": feat.get("Protocol"),
                "Packets": flow["packets"],
                "Bytes": feat.get("Length"),
                "Prediction": pred,
                "Confidence": round(max_prob * 100, 2),
                "Severity": severity_map(pred)
            }

            packets_buffer.append(record)

            if pred != "Normal":
                alerts.append(record)

        except Exception as e:
            print("Error:", e)


# ==================================================
# SNIFFER
# ==================================================

def start_sniffing():
    sniff(
        iface="",
        #iface="MediaTek Wi-Fi 6 MT7921 Wireless LAN Card",
        prn=packet_handler,
        store=False
    )


@app.on_event("startup")
def startup_event():

    thread = threading.Thread(
        target=start_sniffing
    )

    thread.daemon = True
    thread.start()


# ==================================================
# API
# ==================================================

@app.get("/metrics")
def metrics():

    return {        
        "total_packets": len(packets_buffer),
        "total_alerts": len(alerts)
    }


@app.get("/packets")
def packets():
    return packets_buffer


@app.get("/alerts")
def alerts_api():
    return alerts


@app.post("/reset")
def reset_data():
    global packets_buffer, alerts, flows
    packets_buffer.clear()
    alerts.clear()
    flows.clear()
    return {"status": "ok"}