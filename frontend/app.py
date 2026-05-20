import streamlit as st
import requests
import pandas as pd
import time

API = "http://127.0.0.1:8000"

st.set_page_config(page_title="SOC IDS", layout="wide")

st.title("IDS en Tiempo Real")

# -------------------------------
# STATE
# -------------------------------
if "running" not in st.session_state:
    st.session_state.running = False

if "history" not in st.session_state:
    st.session_state.history = []

# -------------------------------
# SIDEBAR
# -------------------------------
st.sidebar.title("Control")

if st.sidebar.button("▶️ Iniciar"):
    st.session_state.running = True

if st.sidebar.button("⏸️ Detener"):
    st.session_state.running = False

# -------------------------------
# PLACEHOLDERS
# -------------------------------
m = st.empty()
t = st.empty()
a = st.empty()
c = st.empty()

# -------------------------------
# LOOP
# -------------------------------
while True:

    if st.session_state.running:

        try:
            metrics = requests.get(f"{API}/metrics").json()
            packets = pd.DataFrame(requests.get(f"{API}/packets").json())
            alerts = pd.DataFrame(requests.get(f"{API}/alerts").json())

            # KPIs
            with m.container():
                c1, c2, c3 = st.columns(3)

                c1.metric("Flujos", metrics["total_packets"])
                c2.metric("Alertas", metrics["total_alerts"])

                c3.metric(
                    "IPs únicas",
                    packets["Source IP"].nunique() if not packets.empty else 0
                )

            # -------------------------------
            # TRAFICO (LIMPIO)
            # -------------------------------
            with t.container():
                st.subheader("📡 Tráfico")

                if not packets.empty:

                    # 🔥 ELIMINAR columnas si existen
                    clean_packets = packets.drop(
                        columns=[col for col in ["Prediction", "Severity"] if col in packets.columns],
                        errors="ignore"
                    )

                    st.dataframe(
                        clean_packets,
                        use_container_width=True
                    )
                else:
                    st.info("Sin tráfico")

            # ALERTAS
            with a.container():
                st.subheader("🚨 Alertas")

                if not alerts.empty:
                    st.dataframe(alerts)

                    st.bar_chart(
                        alerts["Prediction"].value_counts()
                    )
                else:
                    st.info("Sin alertas")

            # HISTORIAL
            st.session_state.history.append({
                "t": time.strftime("%H:%M:%S"),
                "f": metrics["total_packets"],
                "a": metrics["total_alerts"]
            })

            hist = pd.DataFrame(st.session_state.history[-30:])

            # GRÁFICO FINAL
            with c.container():
                st.subheader("📈 Evolución")

                st.line_chart(hist.set_index("t")[["f","a"]])

        except Exception as e:
            st.error(e)

    else:
        st.warning("Detenido")

    time.sleep(5)