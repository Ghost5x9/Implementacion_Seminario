import streamlit as st
import requests
import pandas as pd
import time
from datetime import datetime
import base64

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

bg_main = "#080B12"
bg_card = "#11151E"
bg_card_hover = "#181D28"
text_primary = "#E8EAED"
text_secondary = "#6B7280"
text_muted = "#5F6368"
border_color = "rgba(255,255,255,0.05)"
border_hover = "rgba(255,255,255,0.08)"
sidebar_bg = "linear-gradient(180deg, #0C0F17, #0A0D14)"
table_header = "#11151E"
table_row = "#181D28"
table_row_alt = "#1C2230"
chart_border = "rgba(255,255,255,0.04)"

st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    ::selection {{ background: rgba(66,133,244,0.3); color: #fff; }}
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-track {{ background: {bg_main}; }}
    ::-webkit-scrollbar-thumb {{ background: {text_muted}; border-radius: 3px; }}
    html, body, [class*="css"] {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }}
    .main {{ background-color: {bg_main}; }}
    h1 {{ font-size: 1.8rem !important; font-weight: 800 !important; letter-spacing: -0.5px; color: {text_primary} !important; margin-bottom: 0.2rem !important; }}
    .subtitle {{ color: {text_secondary}; font-size: 0.9rem; font-weight: 400; margin-top: -0.3rem; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid {border_color}; }}
    h2, h3 {{ color: {text_primary}; font-weight: 600 !important; letter-spacing: -0.3px; margin-top: 0.5rem !important; }}
    h2::before, h3::before {{ content: ''; display: inline-block; width: 3px; height: 16px; background: #4285F4; border-radius: 2px; margin-right: 8px; vertical-align: middle; }}
    p {{ color: {text_secondary}; }}
    .stMetric {{ background: linear-gradient(145deg, {bg_card}, {bg_card_hover}); border-radius: 14px; padding: 20px 24px; border: 1px solid {border_color}; box-shadow: 0 4px 24px rgba(0,0,0,0.3); transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; }}
    .stMetric::before {{ content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 2px; background: linear-gradient(90deg, transparent, rgba(66,133,244,0.3), transparent); }}
    .stMetric:hover {{ transform: translateY(-2px); box-shadow: 0 8px 32px rgba(0,0,0,0.5); border-color: {border_hover}; }}
    .stMetric label {{ font-size: 0.75rem !important; font-weight: 600 !important; color: {text_secondary} !important; text-transform: uppercase; letter-spacing: 0.8px; }}
    .stMetric [data-testid="stMetricValue"] {{ font-size: 2rem !important; font-weight: 700 !important; color: {text_primary}; }}
    [data-testid="stDataFrame"] {{ border-radius: 12px; border: 1px solid {border_color}; overflow: hidden; box-shadow: 0 2px 16px rgba(0,0,0,0.2); }}
    [data-testid="stDataFrame"] table {{ font-size: 0.85rem; }}
    [data-testid="stDataFrame"] thead tr th {{ background-color: {table_header} !important; color: {text_secondary} !important; font-weight: 600 !important; font-size: 0.7rem !important; text-transform: uppercase; letter-spacing: 0.8px; padding: 14px 16px !important; border-bottom: 1px solid {border_color} !important; }}
    [data-testid="stDataFrame"] tbody tr td {{ padding: 10px 16px !important; border-bottom: 1px solid transparent !important; }}
    [data-testid="stDataFrame"] tbody tr:nth-child(even) td {{ background-color: {table_row_alt} !important; }}
    [data-testid="stDataFrame"] tbody tr:hover td {{ background-color: rgba(66,133,244,0.04) !important; }}
    [data-testid="stTable"] {{ border-radius: 12px; overflow: hidden; box-shadow: 0 2px 16px rgba(0,0,0,0.2); }}
    [data-testid="stTable"] th {{ background-color: {table_header} !important; color: {text_secondary} !important; font-weight: 600 !important; font-size: 0.7rem !important; text-transform: uppercase; letter-spacing: 0.8px; padding: 12px 16px !important; }}
    [data-testid="stTable"] td {{ background-color: {table_row} !important; color: {text_primary} !important; padding: 10px 16px !important; }}
    [data-testid="stTable"] tr:nth-child(even) td {{ background-color: {table_row_alt} !important; }}
    .block-container {{ padding-top: 1.5rem; padding-bottom: 2rem; }}
    hr {{ border: none; height: 1px; background: linear-gradient(90deg, transparent, {border_color}, transparent); margin: 1.5rem 0; }}
    .stButton button {{ border-radius: 10px !important; font-weight: 600 !important; font-size: 0.85rem !important; padding: 7px 18px !important; transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1) !important; border: 1px solid {border_color} !important; background: {bg_card} !important; color: {text_primary} !important; }}
    .stButton button:hover {{ transform: translateY(-1px); box-shadow: 0 6px 24px rgba(0,0,0,0.4); border-color: {border_hover} !important; background: {bg_card_hover} !important; }}
    .sidebar-status {{ display: flex; align-items: center; gap: 8px; padding: 10px 14px; border-radius: 10px; font-size: 0.8rem; font-weight: 600; margin-bottom: 10px; }}
    .sidebar-status.active {{ background: rgba(0,230,118,0.08); color: #00E676; border: 1px solid rgba(0,230,118,0.15); }}
    .sidebar-status.inactive {{ background: rgba(255,82,82,0.08); color: #FF5252; border: 1px solid rgba(255,82,82,0.15); }}
    .status-dot {{ width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }}
    .status-dot.active {{ background: #00E676; box-shadow: 0 0 12px rgba(0,230,118,0.6); animation: pulse 1.5s ease-in-out infinite; }}
    .status-dot.inactive {{ background: #FF5252; }}
    @keyframes pulse {{ 0%,100% {{ opacity: 1; }} 50% {{ opacity: 0.3; }} }}
    @keyframes glow-critical {{ 0%,100% {{ box-shadow: 0 0 0 rgba(255,23,68,0); }} 50% {{ box-shadow: 0 0 20px rgba(255,23,68,0.3); }} }}
    .stAlert {{ border-radius: 10px; border: none !important; padding: 12px 16px; }}
    .stAlert.success {{ background: rgba(0,230,118,0.06) !important; }}
    .stAlert.info {{ background: rgba(66,133,244,0.06) !important; }}
    .stAlert.warning {{ background: rgba(255,215,64,0.06) !important; }}
    .stAlert.error {{ background: rgba(255,23,68,0.06) !important; }}
    [data-testid="stCaption"] {{ color: {text_muted}; font-size: 0.75rem; letter-spacing: 0.2px; }}
    section[data-testid="stSidebar"] > div:first-child {{ background: {sidebar_bg}; border-right: 1px solid {border_color}; }}
    section[data-testid="stSidebar"] .stButton button {{ background: transparent !important; }}
    section[data-testid="stSidebar"] .stButton button:hover {{ background: rgba(255,255,255,0.04) !important; }}
    .fresco-ahora {{ color: #00E676; font-weight: 600; }}
    .fresco-reciente {{ color: #FFD740; font-weight: 600; }}
    .fresco-antiguo {{ color: #FF5252; font-weight: 600; }}
    div[data-testid="stTextInput"] input {{ background-color: {bg_card} !important; border: 1px solid {border_color} !important; border-radius: 10px !important; color: {text_primary} !important; }}
    div[data-testid="stTextInput"] input:focus {{ border-color: rgba(66,133,244,0.3) !important; box-shadow: 0 0 0 2px rgba(66,133,244,0.08) !important; }}
    div[data-testid="stVerticalBlock"] > div > div > div > div {{ gap: 0.3rem; }}
    [data-testid="stChart"] {{ border-radius: 12px; overflow: hidden; border: 1px solid {chart_border}; }}
    .glow-critical {{
        animation: glow-critical 1.5s ease-in-out 3;
        border-radius: 14px;
    }}
    .severity-card {{
        display: flex; justify-content: space-between; align-items: center;
        padding: 12px 16px; border-radius: 10px; margin-bottom: 6px;
        border: 1px solid {border_color};
    }}
</style>
""", unsafe_allow_html=True)

# ==================================================
# TÍTULO
# ==================================================

st.title("🛡️ Dashboard")
st.markdown(f'<p class="subtitle">Sistema de detección de intrusiones</p>', unsafe_allow_html=True)

# ==================================================
# ESTADO DE SESIÓN
# ==================================================

for key, default in [("running", False), ("history", []), ("last_fetch", None),
                      ("pause_cycles", 0), ("prev_crit_count", 0)]:
    if key not in st.session_state:
        st.session_state[key] = default

# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.title("⚙️ Control")
st.sidebar.caption("Panel de monitoreo en tiempo real")

# --- Indicador de estado ---
status_class = "active" if st.session_state.running else "inactive"
status_text = "En ejecución" if st.session_state.running else "Detenido"
st.sidebar.markdown(
    f'<div class="sidebar-status {status_class}">'
    f'<span class="status-dot {status_class}"></span>{status_text}</div>',
    unsafe_allow_html=True
)

# --- Botones de control ---
iniciar_btn = st.sidebar.button("▶️ Iniciar", use_container_width=True, type="primary")
detener_btn = st.sidebar.button("⏸️ Detener", use_container_width=True, type="secondary")
if iniciar_btn and not st.session_state.running:
    st.session_state.running = True
if detener_btn and st.session_state.running:
    st.session_state.running = False

# --- Selector de interfaz ---
st.sidebar.markdown("##### 🌐 Interfaz")
try:
    ifaces_resp = requests.get(f"{API}/interfaces", timeout=3).json()
    ifaces_raw = ifaces_resp.get("interfaces", [])
    ifaces_friendly = ifaces_resp.get("friendly", ifaces_raw)
    current_iface = ifaces_resp.get("current", "auto")
    iface_opts = ["(automática)"] + ifaces_friendly
    iface_idx = 0
    if current_iface and current_iface != "auto":
        for i, name in enumerate(ifaces_raw):
            if name == current_iface:
                iface_idx = i + 1
                break
    sel_label = st.sidebar.selectbox(
        "Red a monitorear",
        options=iface_opts,
        index=iface_idx,
        label_visibility="collapsed"
    )
    sel_idx = iface_opts.index(sel_label) if sel_label in iface_opts else 0
    req_iface = "" if sel_idx == 0 else ifaces_raw[sel_idx - 1]
    active = "" if current_iface == "auto" else current_iface
    if req_iface != active:
        requests.post(f"{API}/interface", params={"iface": req_iface}, timeout=3)
except:
    st.sidebar.caption("🌐 No se pudieron cargar interfaces")

st.sidebar.markdown("---")

# --- Info de actualización ---
sidebar_time = st.sidebar.empty()
st.sidebar.caption("🔄 Actualización cada 5 segundos")

# --- Limpiar datos ---
st.sidebar.markdown("##### 🧹 Datos")
if st.sidebar.button("🗑️ Limpiar todo", use_container_width=True):
    st.session_state.history = []
    st.session_state.prev_crit_count = 0
    try:
        requests.post(f"{API}/reset", timeout=5)
    except:
        pass
    st.session_state.pause_cycles = 2
    st.session_state.cleanup_time = time.strftime("%H:%M:%S")
    st.toast("🧹 Datos limpiados — nuevos datos aparecerán en breve", icon="✅")

if "cleanup_time" in st.session_state:
    st.sidebar.caption(
        f"🧽 Última limpieza: **{st.session_state.cleanup_time}**"
    )

st.sidebar.markdown("---")


# ==================================================
# PLACEHOLDERS
# ==================================================

metrics_placeholder = st.empty()
alerts_placeholder = st.empty()
traffic_placeholder = st.empty()
chart_placeholder = st.empty()

# ==================================================
# CSV EXPORT
# ==================================================

def descargar_csv(df, nombre):
    csv = df.to_csv(index=False).encode("utf-8")
    b64 = base64.b64encode(csv).decode()
    href = f'<a href="data:text/csv;base64,{b64}" download="{nombre}.csv" style="color:{text_primary};">📥 Exportar {nombre}</a>'
    return href

# ==================================================
# LOOP PRINCIPAL
# ==================================================

while True:

    running = st.session_state.running

    if running:

        if st.session_state.pause_cycles > 0:
            st.session_state.pause_cycles -= 1
            with metrics_placeholder.container():
                st.info("🧹 Datos limpiados. Esperando nuevos paquetes...")
            time.sleep(5)
            continue

        try:

            start_fetch = time.time()

            metrics = requests.get(f"{API}/metrics", timeout=10).json()
            packets_raw = requests.get(f"{API}/packets", timeout=10).json()
            alerts_raw = requests.get(f"{API}/alerts", timeout=10).json()
            stats_raw = requests.get(f"{API}/stats", timeout=10).json()

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

            sidebar_time.markdown(f"📡 {now} · {frescura}", unsafe_allow_html=True)

            # ==========================================
            # MÉTRICAS
            # ==========================================

            with metrics_placeholder.container():

                st.subheader("📊 Métricas")
                st.caption("Resumen del tráfico analizado, alertas generadas y hosts involucrados.")

                c1, c2, c3 = st.columns(3)

                c1.metric("📡 Paquetes", metrics["total_packets"])
                c2.metric("🚨 Alertas", metrics["total_alerts"])
                c3.metric("🌐 IPs Únicas", packets["Source IP"].nunique() if not packets.empty else 0)

                # Nivel de riesgo
                sev_counts = stats_raw.get("by_severity", {})
                if sev_counts:
                    st.markdown("##### Nivel de riesgo")
                    col_s1, col_s2, col_s3 = st.columns(3)
                    col_s1.metric("🟡 Medio", sev_counts.get("🟡 Medio", 0))
                    col_s2.metric("🟠 Alto", sev_counts.get("🟠 Alto", 0))
                    col_s3.metric("🔴 Crítico", sev_counts.get("🔴 Crítico", 0))

                    crit_actual = sev_counts.get("🔴 Crítico", 0)
                    if crit_actual > st.session_state.prev_crit_count:
                        col_s3.markdown(
                            '<div class="glow-critical" style="padding:0;margin:0;height:0"></div>',
                            unsafe_allow_html=True
                        )
                    st.session_state.prev_crit_count = crit_actual

                st.caption(f"Resumen general · {now}")

            # ==========================================
            # ALERTAS
            # ==========================================
            with alerts_placeholder.container():

                st.subheader("🚨 Alertas detectadas")
                st.caption("Eventos clasificados como amenazas con su nivel de riesgo y tipo de ataque.")

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

                    st.caption(f"Mostrando las últimas {len(alert_view)} alertas")
                    st.markdown(descargar_csv(alert_view, "alertas_ids"), unsafe_allow_html=True)

                    def badge_severity(val):

                        badges = {
                            "🟡 Medio": "background: rgba(255,179,0,0.15); color: #FFB300; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.8rem;",
                            "🟠 Alto": "background: rgba(255,87,34,0.15); color: #FF5722; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.8rem;",
                            "🔴 Crítico": "background: rgba(255,23,68,0.15); color: #FF1744; padding: 2px 10px; border-radius: 12px; font-weight: 600; font-size: 0.8rem;"
                        }
                        return badges.get(val, "")

                    styled = alert_view.style.map(badge_severity, subset=["Nivel de Riesgo"])
                    st.dataframe(styled, use_container_width=True, height=350)

                    col1, col2 = st.columns([1, 1])

                    with col1:
                        st.subheader("📋 Flujos por tipo de clase")
                        pred_counts = stats_raw.get("by_prediction", {})
                        normal_count = max(metrics["total_packets"] - stats_raw.get("total_alerts", 0), 0)
                        clases_orden = ["Normal", "Port scan", "Vulnerability scan", "DoS"]
                        clases = {c: 0 for c in clases_orden}
                        clases["Normal"] = normal_count
                        for k, v in pred_counts.items():
                            if k in clases:
                                clases[k] = v
                        classes_df = pd.DataFrame(
                            list(clases.items()),
                            columns=["Tipo de clase", "Cantidad"]
                        )
                        st.table(classes_df)

                    with col2:
                        st.subheader("📊 Tipos de ataque")
                        if pred_counts:
                            attack_df = pd.DataFrame(
                                list(pred_counts.items()),
                                columns=["Tipo", "Cantidad"]
                            ).set_index("Tipo")
                            st.bar_chart(attack_df)

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
                st.caption("Todos los paquetes capturados con protocolo, tamaño y total acumulado por flujo.")

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

                    st.caption(f"Mostrando {len(traffic_view)} paquetes")
                    st.markdown(descargar_csv(traffic_view, "trafico_red"), unsafe_allow_html=True)
                    st.dataframe(traffic_view, use_container_width=True, height=350)

                else:
                    st.info("📭 Esperando tráfico...")
                    st.caption("El tráfico aparecerá automáticamente cuando se detecten paquetes en la red.")

            # ==========================================
            # HISTÓRICO
            # ==========================================

            st.session_state.history.append({
                "Hora": time.strftime("%H:%M:%S"),
                "Paquetes": metrics["total_packets"],
                "Alertas": metrics["total_alerts"]
            })
            st.session_state.history = st.session_state.history[-30:]

            hist = pd.DataFrame(st.session_state.history)

            # ==========================================
            # EVOLUCIÓN DEL SISTEMA
            # ==========================================

            with chart_placeholder.container():

                st.subheader("📈 Evolución del tráfico")
                st.caption("Histórico de paquetes y alertas por minuto para visualizar picos de actividad.")

                if len(hist) > 1:

                    chart_data = hist.set_index("Hora")[["Paquetes", "Alertas"]]
                    max_vals = chart_data.max()

                    if max_vals["Alertas"] > 0 and max_vals["Paquetes"] > 0:
                        chart_norm = chart_data.copy()
                        for col in chart_norm.columns:
                            chart_norm[col] = (chart_norm[col] / max_vals[col]) * 100
                        st.line_chart(chart_norm)
                        max_p = max_vals["Paquetes"]
                        max_a = max_vals["Alertas"]
                        st.caption(f"📐 Escala normalizada · Paquetes: 0–{int(max_p)} | Alertas: 0–{int(max_a)}")
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

        sidebar_time.empty()
        st.warning("⏸️ Monitoreo detenido")
        st.caption("Presiona **▶️ Iniciar** en la barra lateral para comenzar.")

    time.sleep(5)