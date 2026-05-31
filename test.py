import streamlit as st
import pandas as pd

st.set_page_config(
    page_title="Sistema IDS",
    layout="wide"
)

st.title("🔐 Sistema de Detección de Intrusiones")

# -----------------------------------
# SIDEBAR
# -----------------------------------

st.sidebar.header("⚙️ Control del sistema")

st.sidebar.button("▶️ Iniciar monitoreo")
st.sidebar.button("⏹️ Detener monitoreo")

# -----------------------------------
# MÉTRICAS
# -----------------------------------

col1, col2 = st.columns(2)

with col1:
    st.metric(
        "📦 Total de paquetes",
        "12,540"
    )

with col2:
    st.metric(
        "🚨 Alertas generadas",
        "342"
    )

st.divider()

# -----------------------------------
# TRÁFICO DE RED
# -----------------------------------

st.subheader("📡 Tráfico de red")

df_trafico = pd.DataFrame({
    "IP Origen": [
        "192.168.1.10",
        "192.168.1.15",
        "192.168.1.20",
        "192.168.1.25"
    ],
    "IP Destino": [
        "192.168.1.1",
        "192.168.1.1",
        "192.168.1.1",
        "192.168.1.1"
    ],
    "Protocolo": [
        "TCP",
        "UDP",
        "ICMP",
        "TCP"
    ],
    "Longitud": [
        60,
        120,
        98,
        75
    ]
})

st.dataframe(
    df_trafico,
    use_container_width=True
)

st.divider()

# -----------------------------------
# ALERTAS DETECTADAS
# -----------------------------------

st.subheader("🚨 Alertas detectadas")

df_alertas = pd.DataFrame({
    "IP Origen": [
        "192.168.1.15",
        "192.168.1.20"
    ],
    "Tipo de ataque": [
        "Port Scan",
        "DoS"
    ],
    "Hora": [
        "10:35:22",
        "10:41:08"
    ],
    "Nivel de riesgo": [
        "Medio",
        "Alto"
    ]
})

st.dataframe(
    df_alertas,
    use_container_width=True
)

st.divider()

# -----------------------------------
# EVOLUCIÓN DEL SISTEMA
# -----------------------------------

st.subheader("📊 Evolución del tráfico")

chart_data = pd.DataFrame({
    "Alertas detectadas": [
        2,
        5,
        3,
        8,
        6,
        10,
        7
    ]
})

st.line_chart(chart_data)