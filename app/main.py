"""
TON_IoT Simulator with FastAPI Health Check
===========================================
Replaces the old synthetic data simulator.
"""
import asyncio
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd
import paho.mqtt.client as mqtt
from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

YEARLY_CSV = Path(os.getenv("YEARLY_CSV_PATH", "/app/Data/Generated/generated_yearly_merged.csv"))
DEVICES = ["weather", "fridge", "thermostat"]
SENSOR_COLUMNS = {
    "weather":    "temperature",
    "fridge":     "fridge_temperature",
    "thermostat": "current_temperature",
}
ATTACK_TYPES = [
    "backdoor", "DDoS", "DoS", "Injection",
    "MITM", "password", "runsomware", "scanning", "XSS",
]
ATTACK_EXPLANATIONS = {
    "backdoor":   "Backdoor détectée : communication sortante vers IP suspecte.",
    "DDoS":       "DDoS détecté : rafale anormale de requêtes (> 50 msg/s).",
    "DoS":        "DoS détecté : saturation du broker par paquets volumineux.",
    "Injection":  "Injection de payload détectée : séquences d'échappement dans le message.",
    "MITM":       "Man-in-the-Middle détecté : certificat TLS modifié.",
    "password":   "Force brute détectée : > 10 échecs d'authentification en 1 min.",
    "runsomware": "Ransomware détecté : valeurs aberrantes monotones dans les registres.",
    "scanning":   "Scan réseau détecté : balayage de topics MQTT inexistants.",
    "XSS":        "XSS détecté : balises HTML/JavaScript dans le payload.",
}

def inject_anomaly(base_value: float, attack_type: str, noise: float = 0.0) -> float:
    if base_value is None or pd.isna(base_value):
        return base_value
    if attack_type in ("DDoS", "DoS"):
        return base_value * random.uniform(1.5, 3.0) + random.uniform(-2, 2)
    elif attack_type == "backdoor":
        return base_value + random.uniform(-0.5, 0.5)
    elif attack_type == "Injection":
        return base_value * random.uniform(0.1, 0.3) + random.uniform(5, 15)
    elif attack_type == "MITM":
        return base_value + random.uniform(-1.0, 1.0) + noise
    elif attack_type == "runsomware":
        return base_value + random.uniform(2.0, 5.0)
    elif attack_type == "scanning":
        return base_value * random.uniform(0.8, 1.2)
    elif attack_type == "XSS":
        return base_value + random.uniform(-0.3, 0.3)
    elif attack_type == "password":
        return base_value + random.uniform(-0.2, 0.2)
    return base_value

class SeasonalPool:
    def __init__(self, csv_path: Path):
        logger.info("Chargement du dataset annuel : %s", csv_path)
        self.df = pd.read_csv(csv_path)
        self.df["timestamp"] = pd.to_datetime(self.df["timestamp"], errors="coerce")
        self.df = self.df.dropna(subset=["timestamp"])
        logger.info("  %d lignes chargées", len(self.df))

        self._by_season = {}
        for season_id in sorted(self.df["season"].unique()):
            subset = self.df[self.df["season"] == season_id]
            season_name = {1: "hiver", 2: "printemps", 3: "ete", 4: "automne"}.get(season_id, season_id)
            logger.info("  Saison %d (%s) : %d lignes", season_id, season_name, len(subset))
            self._by_season[season_id] = subset.reset_index(drop=True)

    def get_season(self, simulated_date: datetime) -> int:
        month = simulated_date.month
        if month in (12, 1, 2):
            return 1
        elif month in (3, 4, 5):
            return 2
        elif month in (6, 7, 8):
            return 3
        else:
            return 4

    def sample(self, season_id: int, device: str, label: str, attack_type: str = "") -> dict:
        pool = self._by_season.get(season_id, self.df)
        if len(pool) == 0:
            pool = self.df
        row = pool.sample(n=1).iloc[0]

        base_device = device.replace("_attack", "")
        sensor_col = SENSOR_COLUMNS[base_device]
        base_temp = row[sensor_col]

        if label == "attack":
            sensor_value = inject_anomaly(base_temp, attack_type)
        else:
            sensor_value = float(base_temp) + random.uniform(-0.3, 0.3)

        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_type": device,
            sensor_col: round(sensor_value, 2),
            "temperature": float(row["temperature"]),
            "fridge_temperature": float(row["fridge_temperature"]),
            "current_temperature": float(row["current_temperature"]),
            "season": int(row["season"]),
            "month": int(row["month"]),
            "day": int(row["day"]),
            "hour": int(row["hour"]),
            "day_type": row["day_type"],
            "label": label,
            "attack_type": attack_type,
            "attack_explanation": ATTACK_EXPLANATIONS.get(attack_type, ""),
            "noise_factor": round(random.uniform(0.0, 0.06), 4),
            "packet_loss_sim": random.choices([0, 1], weights=[95, 5])[0],
        }
        return payload

def connect_mqtt(host: str, port: int, username: str = None, password: str = None) -> mqtt.Client:
    client = mqtt.Client(client_id="ton-iot-simulator-annual")

    if username and password:
        client.username_pw_set(username, password)

    def on_connect(c, userdata, flags, rc):
        if rc == 0:
            logger.info("Connecte au broker MQTT %s:%d", host, port)
        else:
            logger.error("Connexion MQTT echouee (rc=%d)", rc)

    def on_disconnect(c, userdata, rc):
        logger.warning("Deconnecte du broker MQTT (rc=%d)", rc)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    try:
        client.connect(host, port, keepalive=60)
    except Exception as e:
        logger.error("Impossible de se connecter a %s:%d — %s", host, port, e)
        sys.exit(1)

    client.loop_start()
    return client

async def stream_device(
    mqtt_client: mqtt.Client,
    pool: SeasonalPool,
    device_name: str,
    label: str,
    delay_min: float,
    delay_max: float,
    attack_type: str = "",
) -> None:
    topic = f"factory/{device_name}/telemetry"
    logger.info("Streaming demarre : %s → %s [label=%s, attack=%s]", device_name, topic, label, attack_type or "none")

    while True:
        season_id = random.randint(1, 4)
        row = pool.sample(season_id, device_name, label, attack_type=attack_type)

        payload_json = json.dumps(row, default=str)
        result = mqtt_client.publish(topic, payload_json, qos=1)

        if result.rc != mqtt.MQTT_ERR_SUCCESS:
            logger.warning("Echec publication %s (rc=%d)", topic, result.rc)

        delay = random.uniform(delay_min, delay_max)
        await asyncio.sleep(delay)


class AttackRequest(BaseModel):
    device: str  # one of: fridge, weather, thermostat
    attack_type: str  # one of the ATTACK_TYPES


# FastAPI Application Setup
app = FastAPI(title="iot-simulator-ton-iot", version="2.0.0")

# Module-level MQTT client and pool references (set during startup)
_mqtt_client: Optional[mqtt.Client] = None
_pool: Optional[SeasonalPool] = None

# Background tasks reference to prevent GC
bg_tasks = []


@app.get("/health")
async def health():
    return {"status": "ok", "mode": "ton-iot-multivariate"}


@app.post("/attack")
async def trigger_attack(req: AttackRequest):
    """Publish a single on-demand attack event via MQTT."""
    if _mqtt_client is None or _pool is None:
        return {"status": "error", "reason": "Simulator not ready"}

    base_device = req.device.replace("_attack", "")
    if base_device not in DEVICES:
        return {"status": "error", "reason": f"Unknown device '{req.device}'. Choose from: {DEVICES}"}
    if req.attack_type not in ATTACK_TYPES:
        return {"status": "error", "reason": f"Unknown attack type '{req.attack_type}'. Choose from: {ATTACK_TYPES}"}

    attack_device = f"{base_device}_attack"
    season_id = random.randint(1, 4)
    row = _pool.sample(season_id, attack_device, "attack", attack_type=req.attack_type)

    topic = f"factory/{attack_device}/telemetry"
    payload_json = json.dumps(row, default=str)
    result = _mqtt_client.publish(topic, payload_json, qos=1)

    if result.rc != mqtt.MQTT_ERR_SUCCESS:
        logger.warning("Attack publish failed for %s (rc=%d)", attack_device, result.rc)
        return {"status": "error", "reason": f"MQTT publish failed (rc={result.rc})"}

    logger.info("🚨 Manual attack triggered: device=%s attack=%s → %s", attack_device, req.attack_type, topic)
    return {
        "status": "ok",
        "device": attack_device,
        "attack_type": req.attack_type,
        "topic": topic,
        "payload": row,
    }


@app.on_event("startup")
async def start_simulation():
    global _mqtt_client, _pool

    host = os.getenv("MQTT_HOST", "mosquitto")
    port = int(os.getenv("MQTT_PORT", "1883"))
    username = os.getenv("MQTT_USERNAME", "iot_client")
    password = os.getenv("MQTT_PASSWORD", "iot_password")

    _mqtt_client = connect_mqtt(host, port, username, password)

    # Ensure CSV path exists
    if not YEARLY_CSV.exists():
        logger.error(f"Cannot find dataset at {YEARLY_CSV}! Simulation will not start.")
        return

    _pool = SeasonalPool(YEARLY_CSV)

    # Only stream NORMAL devices continuously — attack devices are triggered on-demand via POST /attack
    for device_name in DEVICES:
        bg_tasks.append(
            asyncio.create_task(
                stream_device(_mqtt_client, _pool, device_name, "normal", 0.5, 2.0)
            )
        )

    logger.info("✅ Normal device simulation started. Attack simulation is MANUAL via POST /attack.")
