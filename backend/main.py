from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import joblib
import pandas as pd
import numpy as np
import time
import threading
import logging
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, get_if_list, conf

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("ids")

app = FastAPI(title="IDS")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================================================
# MODELOS
# ==================================================

model = joblib.load("modelo_xgboost.pkl")
le_attack = joblib.load("label_encoder.pkl")
features = joblib.load("features.pkl")
le_dict = joblib.load("encoders.pkl")
scaler = joblib.load("scaler.pkl")

# ==================================================
# CONFIGURACIÓN
# ==================================================

NET_IFACE = os.getenv("NET_IFACE", "")
CONFIDENCE_THRESHOLD = 0.6
DOS_PACKET_THRESHOLD = 500

# ==================================================
# VARIABLES GLOBALES
# ==================================================

flows = {}
packets_buffer = []
alerts = []
buffer_lock = threading.Lock()
sniffer_stop = threading.Event()
current_iface = NET_IFACE

FLOW_TIMEOUT = 5
NUM_COLS = ['Duration', 'Length', 'TCP Window Size', 'TCP Sequence Number', 'ICMP Type']
TCP_FLAGS = ['TCP Syn', 'TCP ACK', 'TCP FIN', 'TCP RST', 'TCP PSH', 'TCP URG']
NUM_INDICES = [features.index(c) for c in NUM_COLS]

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

    if DNS in pkt:
        data["Protocol"] = "DNS"
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
    elif UDP in pkt:
        data["Protocol"] = "UDP"
    elif ICMP in pkt:
        data["Protocol"] = "ICMP"
        try:
            data["ICMP Type"] = int(pkt[ICMP].type)
        except:
            data["ICMP Type"] = 0
    else:
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
            "data": pkt_info,
            "dos_alerted": False
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
    data["Duration"] = flow["last_time"] - flow["start_time"]
    return data

# ==================================================
# PREPROCESAMIENTO OPTIMIZADO
# ==================================================

def preprocess_single(feat):
    proto = feat.get("Protocol", "UDP")
    if proto not in le_dict['Protocol'].classes_:
        proto = "UDP"
    feat["Protocol"] = int(le_dict['Protocol'].transform([proto])[0])

    row_df = pd.DataFrame([[feat.get(col, 0) for col in features]],
                          columns=features, dtype=np.float64)
    row_df[NUM_COLS] = scaler.transform(row_df[NUM_COLS])
    return row_df.values

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

    try:
        flow = flows[flow_id]
        feat = flow_to_features(flow)
        protocolo_orig = feat.get("Protocol", "")

        X = preprocess_single(feat)

        probs = model.predict_proba(X)[0]

        max_idx = probs.argmax()
        max_prob = float(probs[max_idx])
        pred = le_attack.classes_[max_idx]

        # Umbral base
        umbral = CONFIDENCE_THRESHOLD
        # Paquetes únicos en el flujo → umbral más alto para evitar falsos positivos
        if flow["packets"] <= 3:
            umbral = max(umbral, 0.75)

        if pred != "Normal" and max_prob < umbral:
            pred = "Normal"

        # Filtro: ping simple (ICMP Echo, pocos paquetes) → Normal
        feat_icmp = feat.get("ICMP Type", 0)
        if protocolo_orig == "ICMP" and feat_icmp in (0, 8) and flow["packets"] <= 4:
            pred = "Normal"

        # Regla de volumen: flujo con muchos paquetes → DoS (solo una alerta por flujo)
        if flow["packets"] >= DOS_PACKET_THRESHOLD and not flow["dos_alerted"]:
            pred = "DoS"
            max_prob = 1.0
            flow["dos_alerted"] = True

        record = {
            "Timestamp": time.strftime("%H:%M:%S"),
            "Source IP": flow_id[0],
            "Destination IP": flow_id[1],
            "Protocol": protocolo_orig,
            "Packets": flow["packets"],
            "Bytes": feat.get("Length", 0),
            "Prediction": pred,
            "Confidence": round(max_prob * 100, 2),
            "Severity": severity_map(pred)
        }

        with buffer_lock:
            packets_buffer.append(record)
            if pred != "Normal":
                alerts.append(record)

    except Exception as e:
        log.error("Error en predicción: %s", e)

    expired = [f for f, v in flows.items() if now - v["last_time"] > FLOW_TIMEOUT]
    for fid in expired:
        flows.pop(fid, None)


# ==================================================
# SNIFFER
# ==================================================

def start_sniffing():
    iface = current_iface or None
    log.info("Sniffer iniciado en iface='%s'", iface if iface else "(automática)")
    sniffer_stop.clear()
    sniff(
        iface=iface,
        prn=packet_handler,
        store=False,
        stop_filter=lambda p: sniffer_stop.is_set()
    )
    log.info("Sniffer detenido en iface='%s'", iface if iface else "(automática)")


@app.on_event("startup")
def startup_event():
    log.info("Iniciando IDS backend...")
    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()
    log.info("Backend listo. Interfaz: %s", current_iface or "(automática)")


# ==================================================
# API
# ==================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "packets": len(packets_buffer),
        "alerts": len(alerts),
        "threshold": CONFIDENCE_THRESHOLD
    }


@app.get("/metrics")
def metrics():
    with buffer_lock:
        return {
            "total_packets": len(packets_buffer),
            "total_alerts": len(alerts)
        }


@app.get("/packets")
def packets():
    with buffer_lock:
        return packets_buffer[-2000:]


@app.get("/alerts")
def alerts_api():
    with buffer_lock:
        return alerts[-2000:]


@app.get("/stats")
def stats():
    with buffer_lock:
        total_alerts = len(alerts)
        total_packets = len(packets_buffer)
        pred_counts = {}
        sev_counts = {}
        for a in alerts:
            p = a.get("Prediction", "Unknown")
            s = a.get("Severity", "Unknown")
            pred_counts[p] = pred_counts.get(p, 0) + 1
            sev_counts[s] = sev_counts.get(s, 0) + 1
        return {
            "total_alerts": total_alerts,
            "total_packets": total_packets,
            "by_prediction": pred_counts,
            "by_severity": sev_counts
        }


@app.get("/interfaces")
def list_interfaces():
    raw_list = get_if_list()
    friendly_raw = []
    friendly_filt = []
    for name in raw_list:
        desc = name
        try:
            iface = conf.ifaces.get(name)
            if iface and iface.description:
                desc = f"{iface.description} ({name})"
        except:
            pass
        friendly_raw.append((name, desc))
        lower = desc.lower()
        if any(k in lower for k in ["ethernet", "wi-fi", "wifi", "wireless", "wlan",
                                     "realtek", "intel", "atheros", "broadcom",
                                     "qualcomm", "killer", "régulateur"]):
            friendly_filt.append((name, desc))
    # Si no se encontraron interfaces físicas, mostrar todas
    if not friendly_filt:
        friendly_filt = friendly_raw
    return {
        "interfaces": [x[0] for x in friendly_filt],
        "friendly": [x[1] for x in friendly_filt],
        "current": current_iface or "auto"
    }


@app.post("/interface")
def set_interface(iface: str = ""):
    global current_iface
    raw_list = get_if_list()
    if iface and iface not in raw_list:
        return {"status": "error", "message": f"Interfaz '{iface}' no encontrada"}, 400
    with buffer_lock:
        flows.clear()
    current_iface = iface
    sniffer_stop.set()
    threading.Thread(target=start_sniffing, daemon=True).start()
    log.info("Interfaz cambiada a: %s", iface if iface else "(automática)")
    return {"status": "ok", "interface": iface or "auto"}


@app.post("/reset")
def reset_data():
    global flows
    with buffer_lock:
        packets_buffer.clear()
        alerts.clear()
        flows.clear()
    log.info("Datos limpiados por el usuario")
    return {"status": "ok", "cleared": True}
