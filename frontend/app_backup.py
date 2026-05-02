import streamlit as st
import pandas as pd
import requests
import time

st.set_page_config(page_title="IDS Dashboard", layout="wide")

st.title("🔐 Sistema de Detección de Intrusos (IDS)")

# -------------------------------
# ESTADO
# -------------------------------
if "running" not in st.session_state:
    st.session_state.running = False

# -------------------------------
# SIDEBAR
# -------------------------------
st.sidebar.header("⚙️ Control del sistema")

if st.sidebar.button("▶️ Iniciar monitoreo"):
    st.session_state.running = True

if st.sidebar.button("⏹️ Detener monitoreo"):
    st.session_state.running = False

# -------------------------------
# PLACEHOLDERS
# -------------------------------
metric_col1, metric_col2 = st.columns(2)

col_left, col_right = st.columns([2, 1])

trafico_placeholder = col_left.empty()
result_placeholder = col_left.empty()
alert_placeholder = col_right.empty()
chart_placeholder = st.empty()

# -------------------------------
# LOOP CONTROLADO
# -------------------------------
if st.session_state.running:

    while st.session_state.running:

        try:
            response = requests.get("http://localhost:8000/data")
            data = response.json()
        except:
            st.error("❌ No se pudo conectar con el backend")
            break

        # -------------------------------
        # MÉTRICAS
        # -------------------------------
        metric_col1.metric("📦 Total paquetes", data["total_paquetes"])
        metric_col2.metric("🚨 Ataques detectados", data["total_ataques"])

        # -------------------------------
        # TRÁFICO
        # -------------------------------
        trafico_placeholder.subheader("📡 Tráfico de red")
        trafico_placeholder.dataframe(pd.DataFrame(data["trafico"]))

        # -------------------------------
        # RESULTADOS
        # -------------------------------
        result_placeholder.subheader("🔍 Resultados del modelo")
        result_placeholder.dataframe(pd.DataFrame(data["resultados"]))

        # -------------------------------
        # ALERTAS
        # -------------------------------
        alert_placeholder.subheader("🚨 Alertas")

        alert_df = pd.DataFrame(data["alertas"])

        if alert_df.empty:
            alert_placeholder.warning("Sin ataques detectados")
        else:
            alert_placeholder.dataframe(alert_df)

        # -------------------------------
        # GRÁFICO
        # -------------------------------
        chart_placeholder.subheader("📊 Comportamiento del tráfico")
        chart_placeholder.line_chart(pd.DataFrame({"Ataques": data["grafico"]}))

        time.sleep(2)