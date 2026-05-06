from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime
import configparser
from typing import Optional

app = FastAPI(title="SOC Cyber-Detector API", description="API avec PostgreSQL")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURATION POSTGRESQL ---
config = configparser.ConfigParser()
config.read('db.config')

DB_CONFIG = {
    "dbname": config['postgresql']['dbname'],
    "user": config['postgresql']['user'],
    "password": config['postgresql']['password'],
    "host": config['postgresql']['host'],
    "port": config['postgresql']['port']
}

class LogEntry(BaseModel):
    hostname: str
    process_name: str
    pid: int
    port: int
    alert_message: str
    bytes_sent: Optional[int] = 0
    query_text: Optional[str] = ""
def get_db_connection():
    """Crée et retourne une connexion à PostgreSQL."""
    return psycopg2.connect(**DB_CONFIG)
def init_db():
    """Initialise la table dans PostgreSQL si elle n'existe pas."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hostname VARCHAR(255),
                process_name VARCHAR(255),
                pid VARCHAR(50),
                port INTEGER,
                alert_message TEXT,
                is_anomaly BOOLEAN,
                remediation_action TEXT
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()
        print("[OK] Base de données PostgreSQL initialisée.")
    except Exception as e:
        print(f"[ERREUR] Impossible de se connecter à PostgreSQL : {e}")

init_db()

pending_actions = []

@app.post("/api/logs/", status_code=201)
def receive_log(log: LogEntry):
    # Règles de gestion (Simulant la détection en attendant l'intégration ML complète)
    is_anomaly = False
    remediation = ""
    
    # Règle 1: Détection de port suspect ou d'outil de reverse shell
    if log.port in [4444, 1337] or log.process_name.lower() in ["nc", "ncat", "netcat", "msfconsole"]:
        is_anomaly = True
        remediation = "Kill Process"
                
    # Règle 2: Détection de commandes shell suspectes (SQL / Exfiltration)
    msg_upper = log.alert_message.upper()
    if "SELECT" in msg_upper or "DROP" in msg_upper or "DELETE" in msg_upper:
        is_anomaly = True
        remediation = "Vérifier Injection / Isoler Machine"
    elif "CURL" in msg_upper or "WGET" in msg_upper:
        is_anomaly = True
        remediation = "Vérifier Exfiltration / Bloquer IP"
        
    # Règle 3: Exfiltration réseau massive
    if log.bytes_sent > 50000:
        is_anomaly = True
        remediation = "Bloquer IP"

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, hostname, process_name, pid, port, alert_message, is_anomaly, remediation_action)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            datetime.datetime.now(),
            log.hostname, 
            log.process_name, 
            log.pid, 
            log.port, 
            log.alert_message, 
            is_anomaly, 
            remediation
        ))
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success", "is_anomaly": is_anomaly, "remediation": remediation}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/alerts/")
def get_alerts(limit: int = 100):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor) 
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s", (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats/")
def get_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE is_anomaly = true")
        anomalies = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT hostname) FROM alerts")
        hosts = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        return {"total_alerts": total, "anomalies": anomalies, "unique_hosts": hosts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/actions/kill/{pid}", status_code=200)
def request_kill_process(pid: str, hostname: str = ""):
    """Reçoit la demande du frontend pour tuer un processus."""
    pending_actions.append({"action": "kill", "pid": pid, "hostname": hostname})
    return {"status": "success", "message": f"Action de destruction du PID {pid} sur {hostname} mise en attente."}

@app.get("/api/actions/pending")
def get_pending_actions():
    """L'agent Osquery interrogera cette route pour savoir s'il doit agir."""
    actions = pending_actions.copy()
    pending_actions.clear() # Vider la file une fois récupérée par l'agent
    return actions