import streamlit as st
import requests
import time
import pandas as pd

API = "http://127.0.0.1:8000"

st.set_page_config(page_title="IDS en Tiempo Real", layout="wide")
st.title("🔐 IDS en Tiempo Real")

metric1 = st.empty()
metric2 = st.empty()
packets_placeholder = st.empty()
alerts_placeholder = st.empty()

while True:
    try:
        metrics = requests.get(f"{API}/metrics").json()
        packets = requests.get(f"{API}/packets").json()
        alerts = requests.get(f"{API}/alerts").json()

        metric1.metric("Total flujos analizados", metrics["total_packets"])
        metric2.metric("Alertas detectadas", metrics["total_alerts"])

        packets_placeholder.subheader("📡 Tráfico")
        packets_placeholder.dataframe(pd.DataFrame(packets))

        alerts_placeholder.subheader("🚨 Alertas")
        alerts_placeholder.dataframe(pd.DataFrame(alerts))

    except:
        st.warning("Esperando conexión con backend...")

    time.sleep(2)