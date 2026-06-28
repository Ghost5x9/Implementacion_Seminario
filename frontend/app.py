import streamlit as st
import requests
import pandas as pd
import time
from datetime import datetime

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
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

    ::selection { background: rgba(66,133,244,0.3); color: #fff; }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0A0D14; }
    ::-webkit-scrollbar-thumb { background: #2D3139; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #3D4149; }

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    .main { background-color: #080B12; }

    /* TITLE */
    h1 {
        font-size: 1.8rem !important;
        font-weight: 800 !important;
        letter-spacing: -0.5px;
        background: linear-gradient(135deg, #E8EAED 60%, #6C9BD2);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem !important;
    }
    .subtitle {
        color: #6B7280;
        font-size: 0.9rem;
        font-weight: 400;
        margin-top: -0.3rem;
        margin-bottom: 1.5rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    h2, h3 {
        color: #E8EAED;
        font-weight: 600 !important;
        letter-spacing: -0.3px;
        margin-top: 0.5rem !important;
    }
    h2::before, h3::before {
        content: '';
        display: inline-block;
        width: 3px;
        height: 16px;
        background: #4285F4;
        border-radius: 2px;
        margin-right: 8px;
        vertical-align: middle;
    }
    p { color: #9AA0A6; }

    /* METRICS */
    .stMetric {
        background: linear-gradient(145deg, #11151E, #181D28);
        border-radius: 14px;
        padding: 20px 24px;
        border: 1px solid rgba(255,255,255,0.05);
        box-shadow: 0 4px 24px rgba(0,0,0,0.3);
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }
    .stMetric::before {
        content: '';
        position: absolute;
        top: 0; left: 0;
        width: 100%; height: 2px;
        background: linear-gradient(90deg, transparent, rgba(66,133,244,0.3), transparent);
    }
    .stMetric:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 32px rgba(0,0,0,0.5);
        border-color: rgba(255,255,255,0.08);
    }
    .stMetric label {
        font-size: 0.75rem !important;
        font-weight: 600 !important;
        color: #6B7280 !important;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }
    .stMetric [data-testid="stMetricValue"] {
        font-size: 2rem !important;
        font-weight: 700 !important;
        color: #F0F2F5;
    }

    /* DATAFRAME */
    [data-testid="stDataFrame"] {
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.05);
        overflow: hidden;
        box-shadow: 0 2px 16px rgba(0,0,0,0.2);
    }
    [data-testid="stDataFrame"] table { font-size: 0.85rem; }
    [data-testid="stDataFrame"] thead tr th {
        background-color: #11151E !important;
        color: #6B7280 !important;
        font-weight: 600 !important;
        font-size: 0.7rem !important;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        padding: 14px 16px !important;
        border-bottom: 1px solid rgba(255,255,255,0.04) !important;
    }
    [data-testid="stDataFrame"] tbody tr td {
        padding: 10px 16px !important;
        border-bottom: 1px solid rgba(255,255,255,0.02) !important;
    }
    [data-testid="stDataFrame"] tbody tr:nth-child(even) td {
        background-color: rgba(255,255,255,0.02) !important;
    }
    [data-testid="stDataFrame"] tbody tr:hover td {
        background-color: rgba(66,133,244,0.04) !important;
    }

    /* TABLE */
    [data-testid="stTable"] {
        border-radius: 12px;
        overflow: hidden;
        box-shadow: 0 2px 16px rgba(0,0,0,0.2);
    }
    [data-testid="stTable"] th {
        background-color: #11151E !important;
        color: #6B7280 !important;
        font-weight: 600 !important;
        font-size: 0.7rem !important;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        padding: 12px 16px !important;
        border-bottom: 1px solid rgba(255,255,255,0.04) !important;
    }
    [data-testid="stTable"] td {
        background-color: #181D28 !important;
        color: #E8EAED !important;
        padding: 10px 16px !important;
        border-bottom: 1px solid rgba(255,255,255,0.03);
    }
    [data-testid="stTable"] tr:nth-child(even) td {
        background-color: #1C2230 !important;
    }

    /* LAYOUT */
    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }

    /* DIVIDER */
    hr {
        border: none;
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(255,255,255,0.06), transparent);
        margin: 1.5rem 0;
    }

    /* BUTTONS */
    .stButton button {
        border-radius: 10px !important;
        font-weight: 600 !important;
        font-size: 0.85rem !important;
        padding: 7px 18px !important;
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important;
        border: 1px solid rgba(255,255,255,0.06) !important;
        background: #1A1F2B !important;
        color: #E8EAED !important;
    }
    .stButton button:hover {
        transform: translateY(-1px);
        box-shadow: 0 6px 24px rgba(0,0,0,0.4);
        border-color: rgba(255,255,255,0.12) !important;
        background: #1E2432 !important;
    }
    .stButton button:active {
        transform: translateY(0);
    }

    /* SIDEBAR STATUS */
    .sidebar-status {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        border-radius: 10px;
        font-size: 0.8rem;
        font-weight: 600;
        margin-bottom: 10px;
    }
    .sidebar-status.active {
        background: rgba(0,230,118,0.08);
        color: #00E676;
        border: 1px solid rgba(0,230,118,0.15);
    }
    .sidebar-status.inactive {
        background: rgba(255,82,82,0.08);
        color: #FF5252;
        border: 1px solid rgba(255,82,82,0.15);
    }
    .status-dot {
        width: 8px; height: 8px;
        border-radius: 50%;
        display: inline-block;
        flex-shrink: 0;
    }
    .status-dot.active {
        background: #00E676;
        box-shadow: 0 0 12px rgba(0,230,118,0.6);
        animation: pulse 1.5s ease-in-out infinite;
    }
    .status-dot.inactive { background: #FF5252; }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

    /* ALERTS */
    .stAlert {
        border-radius: 10px;
        border: none !important;
        padding: 12px 16px;
    }
    .stAlert.success { background: rgba(0,230,118,0.06) !important; }
    .stAlert.info { background: rgba(66,133,244,0.06) !important; }
    .stAlert.warning { background: rgba(255,215,64,0.06) !important; }
    .stAlert.error { background: rgba(255,23,68,0.06) !important; }

    /* CAPTION */
    [data-testid="stCaption"] {
        color: #5F6368;
        font-size: 0.75rem;
        letter-spacing: 0.2px;
    }

    /* SIDEBAR */
    section[data-testid="stSidebar"] > div:first-child {
        background: linear-gradient(180deg, #0C0F17, #0A0D14);
        border-right: 1px solid rgba(255,255,255,0.03);
    }
    section[data-testid="stSidebar"] .stButton button {
        background: transparent !important;
    }
    section[data-testid="stSidebar"] .stButton button:hover {
        background: rgba(255,255,255,0.04) !important;
    }

    /* FRESCURA */
    .fresco-ahora { color: #00E676; font-weight: 600; }
    .fresco-reciente { color: #FFD740; font-weight: 600; }
    .fresco-antiguo { color: #FF5252; font-weight: 600; }

    /* WIDGETS */
    div[data-testid="stTextInput"] input {
        background-color: #11151E !important;
        border: 1px solid rgba(255,255,255,0.06) !important;
        border-radius: 10px !important;
        color: #E8EAED !important;
    }
    div[data-testid="stTextInput"] input:focus {
        border-color: rgba(66,133,244,0.3) !important;
        box-shadow: 0 0 0 2px rgba(66,133,244,0.08) !important;
    }

    /* SIDEBAR TITLE */
    .css-10pw50, .stSidebar .css-1v3fvcr {
        font-weight: 700 !important;
        font-size: 1.1rem !important;
    }

    /* SPACING */
    div[data-testid="stVerticalBlock"] > div > div > div > div {
        gap: 0.3rem;
    }

    /* CHART */
    [data-testid="stChart"] {
        border-radius: 12px;
        overflow: hidden;
        border: 1px solid rgba(255,255,255,0.04);
    }
</style>
""", unsafe_allow_html=True)

# ==================================================
# TÍTULO
# ==================================================

st.title("🛡️ Dashboard")
st.markdown('<p class="subtitle">Sistema de detección de intrusiones</p>', unsafe_allow_html=True)

# ==================================================
# ESTADO DE SESIÓN
# ==================================================

if "running" not in st.session_state:
    st.session_state.running = False

if "history" not in st.session_state:
    st.session_state.history = []

if "last_fetch" not in st.session_state:
    st.session_state.last_fetch = None

if "confirm_stop" not in st.session_state:
    st.session_state.confirm_stop = False

# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.title("⚙️ Control")

status_class = "active" if st.session_state.running else "inactive"
status_text = "En ejecución" if st.session_state.running else "Detenido"
st.sidebar.markdown(
    f'<div class="sidebar-status {status_class}">'
    f'<span class="status-dot {status_class}"></span>'
    f'{status_text}</div>',
    unsafe_allow_html=True
)

if st.sidebar.button("▶️ Iniciar", use_container_width=True):
    st.session_state.running = True
    st.session_state.confirm_stop = False
    st.toast("Monitoreo iniciado", icon="✅")

if st.sidebar.button("⏸️ Detener", use_container_width=True):
    st.session_state.confirm_stop = True

if st.session_state.confirm_stop:
    st.sidebar.warning("¿Detener el monitoreo?")
    c1, c2 = st.sidebar.columns(2)
    with c1:
        if st.button("Sí, detener", use_container_width=True):
            st.session_state.running = False
            st.session_state.confirm_stop = False
            st.toast("Monitoreo detenido", icon="⏸️")
    with c2:
        if st.button("Cancelar", use_container_width=True):
            st.session_state.confirm_stop = False

st.sidebar.markdown("---")
st.sidebar.caption("🔄 Actualización cada 5 segundos")

sidebar_time = st.sidebar.empty()

if st.sidebar.button("🗑️ Limpiar datos", use_container_width=True):
    st.session_state.history = []
    try:
        requests.post(f"{API}/reset", timeout=5)
    except:
        pass
    st.toast("Datos limpiados", icon="🧹")

# ==================================================
# PLACEHOLDERS
# ==================================================

metrics_placeholder = st.empty()
alerts_placeholder = st.empty()
traffic_placeholder = st.empty()
chart_placeholder = st.empty()

# ==================================================
# LOOP PRINCIPAL
# ==================================================

while True:

    if st.session_state.running:

        try:

            start_fetch = time.time()

            metrics = requests.get(
                f"{API}/metrics"
            ).json()

            packets_raw = requests.get(
                f"{API}/packets"
            ).json()

            alerts_raw = requests.get(
                f"{API}/alerts"
            ).json()

            packets = pd.DataFrame(packets_raw) if packets_raw else pd.DataFrame()
            alerts = pd.DataFrame(alerts_raw) if alerts_raw else pd.DataFrame()

            fetch_time = time.time() - start_fetch
            st.session_state.last_fetch = time.time()

            now = datetime.now().strftime("%H:%M:%S")

            if fetch_time < 0.5:
                frescura = '<span class="fresco-ahora">en tiempo real</span>'
            elif fetch_time < 2:
                frescura = '<span class="fresco-reciente">actualizado</span>'
            else:
                frescura = '<span class="fresco-antiguo">latencia alta</span>'

            sidebar_time.markdown(
                f"📡 {now} · {frescura}",
                unsafe_allow_html=True
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
                    f"Resumen general · {now}"
                )

            # ==========================================
            # ALERTAS
            # ==========================================

            with alerts_placeholder.container():

                st.subheader("🚨 Alertas detectadas")

                if not alerts.empty:

                    alert_view = alerts[
                        ["Timestamp", "Source IP", "Destination IP",
                         "Prediction", "Severity"]
                    ].rename(columns={
                        "Timestamp": "Hora",
                        "Source IP": "IP Origen",
                        "Destination IP": "IP Destino",
                        "Prediction": "Tipo de Ataque",
                        "Severity": "Nivel de Riesgo"
                    })

                    def badge_severity(val):
                        badges = {
                            "🟢 Bajo": "background: rgba(0,230,118,0.15); color: #00E676; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.8rem;",
                            "🟡 Medio": "background: rgba(255,215,64,0.15); color: #FFD740; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.8rem;",
                            "🟠 Alto": "background: rgba(255,145,0,0.15); color: #FF9100; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.8rem;",
                            "🔴 Crítico": "background: rgba(255,23,68,0.15); color: #FF1744; padding: 2px 10px; border-radius: 12px; font-weight: 700; font-size: 0.8rem;"
                        }
                        return badges.get(val, "")

                    styled = alert_view.style.map(badge_severity, subset=["Nivel de Riesgo"])
                    st.dataframe(styled, use_container_width=True, height=350)

                    # DISTRIBUCIÓN
                    col1, col2 = st.columns([1, 1])

                    with col1:
                        st.subheader("📋 Flujos por tipo de clase")
                        normal_count = max(metrics["total_packets"] - len(alerts), 0)
                        all_classes = pd.concat([
                            alerts["Prediction"],
                            pd.Series(["Normal"] * normal_count)
                        ])
                        class_counts = all_classes.value_counts().sort_index()
                        class_counts_df = pd.DataFrame({
                            "Tipo de clase": class_counts.index,
                            "Cantidad": class_counts.values
                        })
                        st.table(class_counts_df)

                    with col2:
                        st.subheader("📊 Tipos de ataque")
                        attack_counts = alerts["Prediction"].value_counts()
                        st.bar_chart(attack_counts)

                    # Separador visual entre alertas y tráfico
                    st.markdown("---")

                else:
                    st.success("✅ Todo normal — no se detectaron amenazas")
                    st.caption("Si hay actividad sospechosa, las alertas aparecerán aquí automáticamente.")
                    st.markdown("---")

            # ==========================================
            # TRÁFICO DE RED
            # ==========================================

            with traffic_placeholder.container():

                st.subheader("📡 Tráfico de red")
                st.caption("Información del tráfico capturado y procesado por el sistema.")

                if not packets.empty:

                    traffic_view = packets[
                        ["Timestamp", "Source IP", "Destination IP",
                         "Protocol", "Packets", "Bytes"]
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
                    st.info("📭 Esperando tráfico...")
                    st.caption("El tráfico aparecerá automáticamente cuando se detecten paquetes en la red.")

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

                st.subheader("📈 Evolución del tráfico")
                st.caption("Evolución histórica de los flujos analizados y alertas detectadas.")

                if len(hist) > 1:

                    chart_data = hist.set_index("Hora")[["Flujos", "Alertas"]]

                    max_vals = chart_data.max()
                    if max_vals["Alertas"] > 0 and max_vals["Flujos"] > 0:
                        chart_norm = chart_data.copy()
                        for col in chart_norm.columns:
                            chart_norm[col] = (chart_norm[col] / max_vals[col]) * 100

                        st.line_chart(chart_norm)

                        max_f = max_vals["Flujos"]
                        max_a = max_vals["Alertas"]
                        st.caption(
                            f"📐 Escala normalizada · Flujos: 0–{int(max_f)} | Alertas: 0–{int(max_a)}"
                        )
                    else:
                        st.line_chart(chart_data)

                else:
                    st.caption("Acumulando datos históricos para mostrar tendencia...")

        except requests.exceptions.ConnectionError:
            st.error("🔌 No se pudo conectar con el backend. Verifica que la API esté corriendo en http://127.0.0.1:8000")
            sidebar_time.empty()

        except Exception as e:
            st.error(f"⚠️ Error inesperado: {e}")

    else:

        if not st.session_state.confirm_stop:
            sidebar_time.empty()
            st.warning("⏸️ Monitoreo detenido")
            st.caption("Presiona **▶️ Iniciar** en la barra lateral para comenzar.")

    time.sleep(5)
