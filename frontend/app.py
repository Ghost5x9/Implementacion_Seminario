import streamlit as st
import requests
import pandas as pd
import time

API = "http://127.0.0.1:8000"

# ==================================================
# CONFIGURACIÓN
# ==================================================

st.set_page_config(
    page_title="Sistema de detección de intrusiones",
    layout="wide"
)

# ==================================================
# ESTILOS
# ==================================================

st.markdown("""
<style>

.main {
    background-color: #0E1117;
}

h1, h2, h3 {
    color: white;
}

.stMetric {
    background-color: #1E1E1E;
    border-radius: 10px;
    padding: 15px;
    border: 1px solid #262730;
}

[data-testid="stDataFrame"] {
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)

# ==================================================
# TÍTULO
# ==================================================

st.title("🛡️ Dashboard")
st.markdown("Sistema de detección de intrusiones")

# ==================================================
# ESTADO DE SESIÓN
# ==================================================

if "running" not in st.session_state:
    st.session_state.running = False

if "history" not in st.session_state:
    st.session_state.history = []

# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.title("⚙️ Control")

if st.sidebar.button("▶️ Iniciar"):
    st.session_state.running = True

if st.sidebar.button("⏸️ Detener"):
    st.session_state.running = False

st.sidebar.markdown("---")
st.sidebar.info("Actualización cada 5 segundos")

# ==================================================
# PLACEHOLDERS
# ==================================================

metrics_placeholder = st.empty()
traffic_placeholder = st.empty()
alerts_placeholder = st.empty()
chart_placeholder = st.empty()

# ==================================================
# LOOP PRINCIPAL
# ==================================================

while True:

    if st.session_state.running:

        try:

            metrics = requests.get(
                f"{API}/metrics"
            ).json()

            packets = pd.DataFrame(
                requests.get(
                    f"{API}/packets"
                ).json()
            )

            alerts = pd.DataFrame(
                requests.get(
                    f"{API}/alerts"
                ).json()
            )

            # ==========================================
            # MÉTRICAS
            # ==========================================

            with metrics_placeholder.container():

                c1, c2, c3 = st.columns(3)

                c1.metric(
                    "📡 Flujos",
                    metrics["total_packets"]
                )

                c2.metric(
                    "🚨 Alertas",
                    metrics["total_alerts"]
                )

                c3.metric(
                    "🌐 IPs Únicas",
                    packets["Source IP"].nunique()
                    if not packets.empty else 0
                )

                st.caption(
                    "Resumen general del estado actual del sistema de monitoreo."
                )

            # ==========================================
            # TRÁFICO DE RED
            # ==========================================

            with traffic_placeholder.container():

                st.subheader(
                    "📡 Tráfico de red"
                )

                st.caption(
                    "Información del tráfico capturado y procesado por el sistema."
                )

                if not packets.empty:

                    traffic_view = packets[
                        [
                            "Timestamp",
                            "Source IP",
                            "Destination IP",
                            "Protocol",
                            "Packets",
                            "Bytes"
                        ]
                    ].rename(columns={
                        "Timestamp": "Hora",
                        "Source IP": "IP Origen",
                        "Destination IP": "IP Destino",
                        "Protocol": "Protocolo",
                        "Packets": "Paquetes",
                        "Bytes": "Bytes"
                    })

                    st.dataframe(
                        traffic_view,
                        use_container_width=True,
                        height=350
                    )

                else:

                    st.info("Esperando tráfico...")

            # ==========================================
            # ALERTAS
            # ==========================================

            with alerts_placeholder.container():

                st.subheader(
                    "🚨 Alertas detectadas"
                )

                st.caption(
                    "Registro de eventos de seguridad detectados por el sistema."
                )

                if not alerts.empty:

                    alert_view = alerts[
                        [
                            "Timestamp",
                            "Source IP",
                            "Destination IP",
                            "Prediction",
                            "Severity"
                        ]
                    ].rename(columns={
                        "Timestamp": "Hora",
                        "Source IP": "IP Origen",
                        "Destination IP": "IP Destino",
                        "Prediction": "Tipo de Ataque",
                        "Severity": "Nivel de Riesgo"
                    })

                    col1, col2 = st.columns([2, 1])

                    # TABLA ALERTAS

                    with col1:

                        st.dataframe(
                            alert_view,
                            use_container_width=True,
                            height=350
                        )

                    # GRÁFICO TIPOS DE ATAQUE

                    with col2:

                        st.subheader(
                            "📊 Tipos de ataque"
                        )

                        attack_counts = (
                            alerts["Prediction"]
                            .value_counts()
                        )

                        st.bar_chart(attack_counts)

                else:

                    st.success("No se detectaron amenazas")

            # ==========================================
            # HISTÓRICO
            # ==========================================

            st.session_state.history.append({
                "Hora": time.strftime("%H:%M:%S"),
                "Flujos": metrics["total_packets"],
                "Alertas": metrics["total_alerts"]
            })

            st.session_state.history = (
                st.session_state.history[-30:]
            )

            hist = pd.DataFrame(
                st.session_state.history
            )

            # ==========================================
            # EVOLUCIÓN DEL SISTEMA
            # ==========================================

            with chart_placeholder.container():

                st.subheader(
                    "📈 Evolución del tráfico"
                )

                st.caption(
                    "Evolución histórica de los flujos analizados y alertas detectadas."
                )

                st.line_chart(
                    hist.set_index("Hora")[
                        ["Flujos", "Alertas"]
                    ]
                )

        except Exception as e:

            st.error(f"Error: {e}")

    else:

        st.warning("⏸️ Monitoreo detenido")

    time.sleep(5)