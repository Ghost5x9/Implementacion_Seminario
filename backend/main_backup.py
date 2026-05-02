from fastapi import FastAPI
import random
import time

app = FastAPI()

@app.get("/data")
def get_data():

    trafico = [
        {"Protocol": "TCP", "Length": random.randint(40, 150), "Estado": random.choice(["Normal", "Ataque"])},
        {"Protocol": "UDP", "Length": random.randint(40, 150), "Estado": random.choice(["Normal", "Normal"])},
        {"Protocol": "ICMP", "Length": random.randint(40, 150), "Estado": random.choice(["Ataque", "Normal"])},
    ]

    resultados = [
        {"Protocol": t["Protocol"], "Length": t["Length"], "Prediccion": "DoS" if t["Estado"] == "Ataque" else "Normal"}
        for t in trafico
    ]

    alertas = [
        {"Tipo": r["Prediccion"], "Hora": time.strftime("%H:%M:%S"), "Riesgo": "Alto"}
        for r in resultados if r["Prediccion"] != "Normal"
    ]

    return {
        "total_paquetes": random.randint(10000, 20000),
        "total_ataques": len(alertas),
        "trafico": trafico,
        "resultados": resultados,
        "alertas": alertas,
        "grafico": [random.randint(1, 15) for _ in range(6)]
    }