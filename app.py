import streamlit as st
import pandas as pd
import joblib
import time

# -------------------------------
# CONFIG
# -------------------------------
st.set_page_config(page_title="IDS con XGBoost", layout="wide")
st.title("🔐 Sistema de Detección de Intrusos (IDS)")

# -------------------------------
# CARGAR MODELO Y COMPONENTES
# -------------------------------
@st.cache_resource
def load_all():
    model = joblib.load("modelo_xgboost.pkl")
    le_attack = joblib.load("label_encoder.pkl")
    features = joblib.load("features.pkl")
    le_dict = joblib.load("encoders.pkl")   # LabelEncoders de Protocol e ICMP
    scaler = joblib.load("scaler.pkl")      # StandardScaler
    return model, le_attack, features, le_dict, scaler

model, le_attack, features, le_dict, scaler = load_all()

# -------------------------------
# PREPROCESAMIENTO (IGUAL AL ENTRENAMIENTO)
# -------------------------------
def preprocess(df):
    df = df.copy()

    # eliminar columnas innecesarias
    drop_cols = ["Source", "Destination", "Info", "Label", "Attack Category"]
    df = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")

    # -------------------------------
    # FLAGS TCP → 0/1 (igual que entrenamiento)
    # -------------------------------
    tcp_flags = ['TCP Syn', 'TCP ACK', 'TCP FIN', 'TCP RST', 'TCP PSH', 'TCP URG']

    def convert_flag(val):
        return 1 if str(val).strip() in ['1', 'True', 'true'] else 0

    for col in tcp_flags:
        if col in df.columns:
            df[col] = df[col].apply(convert_flag)

    # -------------------------------
    # LABEL ENCODING (Protocol, ICMP Type)
    # -------------------------------
    for col, le in le_dict.items():
        if col in df.columns:
            df[col] = df[col].astype(str).apply(
                lambda x: le.transform([x])[0] if x in le.classes_ else -1
            )
        else:
            df[col] = -1  # si no existe, valor desconocido

    # -------------------------------
    # ESCALADO (igual que entrenamiento)
    # -------------------------------
    num_cols = ['Duration', 'Length', 'TCP Window Size', 'TCP Sequence Number']

    for col in num_cols:
        if col not in df.columns:
            df[col] = 0

    df[num_cols] = scaler.transform(df[num_cols])

    # -------------------------------
    # ASEGURAR FEATURES EXACTAS
    # -------------------------------
    df = df.reindex(columns=features, fill_value=0)

    return df

# -------------------------------
# SIDEBAR
# -------------------------------
st.sidebar.header("⚙️ Control")
run = st.sidebar.button("▶️ Iniciar monitoreo")
file = st.sidebar.file_uploader("📂 Subir dataset CSV", type=["csv"])

# -------------------------------
# PLACEHOLDERS
# -------------------------------
metric1 = st.empty()
metric2 = st.empty()
data_placeholder = st.empty()
result_placeholder = st.empty()
alert_placeholder = st.empty()
chart_placeholder = st.empty()
debug_placeholder = st.empty()

# -------------------------------
# VARIABLES
# -------------------------------
alerts = []
total_packets = 0
total_attacks = 0

# -------------------------------
# MAIN
# -------------------------------
if run and file is not None:

    data = pd.read_csv(file)

    # mostrar distribución real
    if "Attack Category" in data.columns:
        st.subheader("📊 Distribución REAL del dataset")
        st.write(data["Attack Category"].value_counts())

    chunk_size = 1000

    for i in range(0, len(data), chunk_size):

        chunk = data.iloc[i:i+chunk_size]

        # -------------------------------
        # MOSTRAR TRÁFICO
        # -------------------------------
        data_placeholder.subheader("📡 Tráfico (muestra)")
        data_placeholder.dataframe(chunk.head(20))

        # -------------------------------
        # PREPROCESAR
        # -------------------------------
        X = preprocess(chunk)

        # -------------------------------
        # PREDICCIÓN
        # -------------------------------
        pred_encoded = model.predict(X)
        pred = le_attack.inverse_transform(pred_encoded)

        chunk["Predicción"] = pred

        # -------------------------------
        # DEBUG (MUY IMPORTANTE)
        # -------------------------------
        debug_placeholder.subheader("🧪 Debug del modelo")
        debug_placeholder.write("Predicciones:")
        debug_placeholder.write(pd.Series(pred).value_counts())

        if "Attack Category" in chunk.columns:
            debug_placeholder.write("Reales:")
            debug_placeholder.write(chunk["Attack Category"].value_counts())

        # -------------------------------
        # MÉTRICAS
        # -------------------------------
        total_packets += len(chunk)
        ataques = sum(pred != "Normal")
        total_attacks += ataques

        metric1.metric("Total paquetes", total_packets)
        metric2.metric("Ataques detectados", total_attacks)

        # -------------------------------
        # RESULTADOS
        # -------------------------------
        result_placeholder.subheader("🔍 Resultados")
        result_placeholder.dataframe(
            chunk[["Protocol", "Length", "Predicción"]].head(20)
        )

        # -------------------------------
        # ALERTAS
        # -------------------------------
        nuevas = []
        for p in pred:
            if p != "Normal":
                nuevas.append({
                    "Tipo": p,
                    "Hora": time.strftime("%H:%M:%S"),
                    "Riesgo": "Alto"
                })

        alerts.extend(nuevas)

        alert_placeholder.subheader("🚨 Panel de alertas")
        if alerts:
            alert_placeholder.dataframe(pd.DataFrame(alerts).tail(20))
        else:
            alert_placeholder.warning("⚠️ No se han detectado ataques aún")

        # -------------------------------
        # GRÁFICO
        # -------------------------------
        chart_placeholder.subheader("📊 Distribución acumulada")

        attack_series = pd.Series([a["Tipo"] for a in alerts])

        if not attack_series.empty:
            chart_placeholder.bar_chart(attack_series.value_counts())
        else:
            chart_placeholder.info("Sin datos para graficar")

        time.sleep(2)

else:
    st.info("Sube un archivo y presiona iniciar")