import streamlit as st
import pandas as pd

st.set_page_config(page_title="IDS - Diseño", layout="wide")
st.title("🔐 Sistema de Detección de Intrusos (IDS)")

# -------------------------------
# SIDEBAR (CONTROL)
# -------------------------------
st.sidebar.header("⚙️ Control del sistema")
st.sidebar.button("▶️ Iniciar monitoreo")
st.sidebar.button("⏹️ Detener monitoreo")

# -------------------------------
# MÉTRICAS
# -------------------------------
col1, col2 = st.columns(2)
col1.metric("📦 Total paquetes", "12,540")
col2.metric("🚨 Ataques detectados", "342")

# -------------------------------
# LAYOUT PRINCIPAL
# -------------------------------
col_left, col_right = st.columns([2, 1])

# -------------------------------
# IZQUIERDA → TRÁFICO + RESULTADOS
# -------------------------------
with col_left:
    st.subheader("📡 Tráfico de red")
    df_trafico = pd.DataFrame({
        "Protocol": ["TCP", "UDP", "ICMP", "TCP"],
        "Length": [60, 120, 98, 75],
        "Estado": ["Normal", "Normal", "Ataque", "Normal"]
    })
    st.dataframe(df_trafico)

    st.subheader("🔍 Resultados del modelo")
    df_resultados = pd.DataFrame({
        "Protocol": ["TCP", "ICMP", "UDP"],
        "Length": [60, 98, 120],
        "Predicción": ["Normal", "DoS", "Normal"]
    })
    st.dataframe(df_resultados)

# -------------------------------
# DERECHA → ALERTAS
# -------------------------------
with col_right:
    st.subheader("🚨 Alertas")
    df_alertas = pd.DataFrame({
        "Tipo de ataque": ["DoS", "Port Scan"],
        "Hora": ["10:32:10", "10:35:22"],
        "Nivel de riesgo": ["Alto", "Medio"]
    })
    st.dataframe(df_alertas)

# -------------------------------
# GRÁFICO
# -------------------------------
st.subheader("📊 Comportamiento del tráfico")
chart_data = pd.DataFrame({
    "Ataques": [5, 10, 7, 12]
})
st.line_chart(chart_data)