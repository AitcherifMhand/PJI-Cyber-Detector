from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime
import configparser

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

class AlertEntry(BaseModel):
    process_name: str
    pid: str
    port: int
    alert_message: str

def init_db():
    """Initialise la table dans PostgreSQL si elle n'existe pas."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                process_name VARCHAR(255),
                pid VARCHAR(50),
                port INTEGER,
                alert_message TEXT
            )
        ''')
        conn.commit()
        cursor.close()
        conn.close()
        print("[OK] Base de données PostgreSQL initialisée.")
    except Exception as e:
        print(f"[ERREUR] Impossible de se connecter à PostgreSQL : {e}")

init_db()

@app.post("/api/alerts/", status_code=201)
def create_alert(alert: AlertEntry):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor()
        timestamp = datetime.datetime.now()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, process_name, pid, port, alert_message)
            VALUES (%s, %s, %s, %s, %s)
        ''', (timestamp, alert.process_name, alert.pid, alert.port, alert.alert_message))
        
        conn.commit()
        cursor.close()
        conn.close()
        return {"status": "success", "message": "Alerte insérée dans PostgreSQL."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/alerts/")
def get_alerts():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cursor = conn.cursor(cursor_factory=RealDictCursor) 
        cursor.execute("SELECT id, timestamp, process_name, pid, port, alert_message FROM alerts ORDER BY timestamp DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
pending_actions = []

@app.post("/api/actions/kill/{pid}", status_code=200)
def request_kill_process(pid: str):
    """Reçoit la demande du frontend pour tuer un processus."""
    pending_actions.append({"action": "kill", "pid": pid})
    return {"status": "success", "message": f"Action de destruction du PID {pid} mise en attente."}

@app.get("/api/actions/pending")
def get_pending_actions():
    """L'agent Osquery interrogera cette route pour savoir s'il doit agir."""
    actions = pending_actions.copy()
    pending_actions.clear() # Vider la file une fois récupérée par l'agent
    return actions