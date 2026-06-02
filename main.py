from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime
import configparser
import logging
import logging.handlers
import socket
import json
import requests
import os
from ml.ml_module import CyberAnomalyDetector
from typing import Optional
from dotenv import load_dotenv
import urllib3


load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Chargement du modèle ML

ML_MODEL_PATH = os.environ.get("ML_MODEL_PATH", "ml/ml_behavioral_model.joblib")
detector = CyberAnomalyDetector.load_model(ML_MODEL_PATH)

app = FastAPI(title="SOC Cyber-Detector API", description="API avec PostgreSQL")

CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://localhost:8080").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)
# --- WAZUH CONFIGURATION ---
WAZUH_API_URL  = os.getenv("WAZUH_API_URL", "")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASSWORD", "")
WAZUH_VERIFY_TLS = os.getenv("WAZUH_VERIFY_TLS", "False").lower() in ("true", "1", "t")
WAZUH_SYSLOG_HOST = os.getenv("WAZUH_SYSLOG_HOST", "")   # ex: "192.168.1.10"
WAZUH_SYSLOG_PORT = int(os.getenv("WAZUH_SYSLOG_PORT", "514"))

if not WAZUH_API_URL or not WAZUH_API_USER:
    print("[ERREUR] Configuration Wazuh manquante dans les variables d'environnement.")


log_file_path = os.environ.get("SOC_LOG_PATH", "soc_alerts.json")
logger = logging.getLogger("SOC_Logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_file_path)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)
# Handler syslog UDP → Wazuh manager
if WAZUH_SYSLOG_HOST:
    try:
        syslog_handler = logging.handlers.SysLogHandler(
            address=(WAZUH_SYSLOG_HOST, WAZUH_SYSLOG_PORT),
            socktype=socket.SOCK_DGRAM,
        )
        syslog_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(syslog_handler)
        print(f"[OK] Syslog Wazuh activé → {WAZUH_SYSLOG_HOST}:{WAZUH_SYSLOG_PORT}")
    except Exception as e:
        print(f"[WARN] Impossible d'initialiser le handler syslog : {e}")
else:
    print("[INFO] WAZUH_SYSLOG_HOST non défini — syslog désactivé (fichier local uniquement)")



# --- CONFIGURATION POSTGRESQL ---
config = configparser.ConfigParser()
config.read('db.config')

DB_CONFIG = {
    "dbname": os.getenv("DB_NAME", "soc_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", ""),
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432")
}
class InventoryEntry(BaseModel):
    hostname: str
    packages: list[dict] # Liste de dictionnaires contenant 'name' et 'version' et 'ecosystem'
    
class LogEntry(BaseModel):
    hostname: str
    process_name: str
    pid: int
    port: int
    alert_message: str
    bytes_sent:    Optional[int] = 0
    bytes_received: Optional[int] = 0
    query_text:    Optional[str] = ""
    remote_ip:     Optional[str] = ""
    timestamp:     Optional[str] = None
    
def get_db_connection():
    """Crée et retourne une connexion à PostgreSQL."""
    return psycopg2.connect(**DB_CONFIG)
def init_db():
    """Initialise la table dans PostgreSQL si elle n'existe pas."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS raw_logs (
                id                SERIAL PRIMARY KEY,
                timestamp         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hostname          VARCHAR(255),
                process_name      VARCHAR(255),
                pid               INTEGER,
                port              INTEGER,
                bytes_sent        BIGINT DEFAULT 0,
                remote_ip         VARCHAR(64),
                alert_message     TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id                SERIAL PRIMARY KEY,
                timestamp         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hostname          VARCHAR(255),
                process_name      VARCHAR(255),
                pid               INTEGER,
                port              INTEGER,
                alert_message     TEXT,
                is_anomaly        BOOLEAN DEFAULT FALSE,
                resolved          BOOLEAN DEFAULT FALSE,
                severity          VARCHAR(16),
                risk_score        FLOAT,
                ml_score          FLOAT,
                rules_score       FLOAT,
                remediation_action TEXT,
                reasons           TEXT,
                risk_axes         TEXT,
                bytes_sent        BIGINT DEFAULT 0,
                remote_ip         VARCHAR(64)
            )
        """)
        conn.commit()
        print("[OK] Base de données PostgreSQL initialisée.")
    except Exception as e:
        print(f"[ERREUR] Impossible de se connecter à PostgreSQL : {e}")
    finally:
        try:
            cur.close()
            conn.close()
        except Exception:
            pass

init_db()

# Helper functions pour Wazuh API
def get_wazuh_token() -> str:
    if not WAZUH_API_URL:
        raise RuntimeError("Wazuh non configuré")
    resp = requests.post(
        f"{WAZUH_API_URL}/security/user/authenticate",
        auth=(WAZUH_API_USER, WAZUH_API_PASS),
        verify=WAZUH_VERIFY_TLS,
        timeout=8,
    )
    if resp.status_code == 200:
        return resp.json()["data"]["token"]
    raise RuntimeError(f"Auth Wazuh échouée ({resp.status_code})")

def get_agent_id(hostname: str, token: str) -> Optional[str]:
    resp = requests.get(
        f"{WAZUH_API_URL}/agents?q=name={hostname}",
        headers={"Authorization": f"Bearer {token}"},
        verify=WAZUH_VERIFY_TLS,
        timeout=8,
    )
    items = resp.json().get("data", {}).get("affected_items", [])
    return items[0]["id"] if items else None

def get_wazuh_alerts(token: str, limit: int = 100) -> list:
    resp = requests.get(
        f"{WAZUH_API_URL}/alerts?limit={limit}",
        headers={"Authorization": f"Bearer {token}"},
        verify=WAZUH_VERIFY_TLS,
        timeout=10,
    )
    if resp.status_code == 200:
        return resp.json()["data"]["affected_items"]
    return []

def get_host_behavior_window(hostname: str) -> dict:
    """Reconstruit le comportement de l'hôte sur les dernières 1h, 5m, 1m depuis PostgreSQL."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    # On récupère les agrégats glissants
    cur.execute("""
        SELECT 
            COUNT(CASE WHEN timestamp >= NOW() - INTERVAL '1 minute' THEN 1 END) as req_per_min,
            COUNT(CASE WHEN timestamp >= NOW() - INTERVAL '5 minutes' THEN 1 END) as req_per_5m,
            COUNT(CASE WHEN timestamp >= NOW() - INTERVAL '1 hour' THEN 1 END) as req_per_hour,
            COALESCE(SUM(CASE WHEN timestamp >= NOW() - INTERVAL '1 minute' THEN bytes_sent END), 0) as bytes_sent_1m,
            COALESCE(SUM(CASE WHEN timestamp >= NOW() - INTERVAL '5 minutes' THEN bytes_sent END), 0) as bytes_sent_5m,
            COUNT(DISTINCT CASE WHEN timestamp >= NOW() - INTERVAL '1 hour' THEN port END) as unique_ports_1h,
            COUNT(DISTINCT CASE WHEN timestamp >= NOW() - INTERVAL '1 hour' THEN remote_ip END) as unique_ips_1h
        FROM raw_logs 
        WHERE hostname = %s AND timestamp >= NOW() - INTERVAL '1 hour'
    """, (hostname,))
    
    window_data = cur.fetchone()
    cur.close()
    conn.close()
    
    return dict(window_data)

def format_wazuh_alert(a: dict) -> dict:
    """Convertit une alerte brute Wazuh API en dict dashboard."""
    d = a.get("data", {})
    return {
        "id":                 a.get("id"),
        "timestamp":          a.get("timestamp"),
        "hostname":           a.get("agent", {}).get("name", "Unknown"),
        "process_name":       d.get("process_name", "Unknown"),
        "pid":                d.get("pid", 0),
        "port":               d.get("port", 0),
        "alert_message":      a.get("rule", {}).get("description", ""),
        "is_anomaly":         d.get("is_anomaly", False),
        "severity":           d.get("severity", "INFO"),
        "risk_score":         d.get("risk_score", 0),
        "remediation_action": d.get("remediation_action", ""),
        "resolved":           False,
        "rule_level":         a.get("rule", {}).get("level", 0),
        "soc_source":         d.get("soc_source", ""),
    }

def build_alert_payload(log_dict: dict, result: dict) -> str:
    """Construit le JSON envoyé à Wazuh via syslog et écrit dans le fichier local."""
    return json.dumps({
        "soc_timestamp":          log_dict["timestamp"],
        "soc_hostname":           log_dict["hostname"],
        "soc_process_name":       log_dict["process_name"],
        "soc_pid":                int(log_dict["pid"]),
        "soc_port":               int(log_dict["port"]),
        "soc_alert_message":      log_dict["alert_message"],
        "soc_is_anomaly":         result["is_anomaly"],
        "soc_severity":           result["severity"],
        "soc_risk_score":         result["risk_score"],
        "soc_remediation_action": result["remediation"],
        "soc_reasons":            " | ".join(result["reasons"]),
        "soc_source":             "ml_anomaly",
    })
    
@app.post("/api/logs/", status_code=201)
def receive_log(log: LogEntry):
    """Point d'entrée principal de l'agent Osquery."""
    log_dict = log.dict()
    if not log_dict.get("timestamp"):
        log_dict["timestamp"] = datetime.datetime.utcnow().isoformat()

    # 1. Sauvegarde du log brut d'abord (pour la mémoire ML)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO raw_logs (timestamp, hostname, process_name, pid, port, bytes_sent, remote_ip, alert_message)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (log_dict["timestamp"], log.hostname, log.process_name, log.pid, log.port, log.bytes_sent or 0, log.remote_ip or "", log.alert_message))
    conn.commit()

    # 2. Reconstitution de la mémoire
    wf = get_host_behavior_window(log.hostname)
    log_dict['window_state'] = wf 

    # 3. Évaluation hybride
    result = detector.predict(log_dict) 
    
    # 4. Si c'est une alerte (score élevé ou anomalie), on insère dans la table alerts
    if result["is_anomaly"] or result["rules_score"] > 0:
        cur.execute("""
            INSERT INTO alerts (timestamp, hostname, process_name, pid, port, alert_message, is_anomaly, severity, risk_score, ml_score, rules_score, remediation_action, reasons, risk_axes)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (log_dict["timestamp"], log.hostname, log.process_name, log.pid, log.port, log.alert_message, result["is_anomaly"], result["severity"], result["risk_score"], result["ml_score"], result["rules_score"], result["remediation"], " | ".join(result["reasons"]), json.dumps(result["risk_axes"])))
        conn.commit()
        
        logger.info(build_alert_payload(log_dict, result))

    cur.close()
    conn.close()
    return {
        "status": "success",
        "is_anomaly": result["is_anomaly"],
        "remediation": result["remediation"]
    }
    
     
def check_osv_vulnerabilities_batch(packages):
    """Interroge l'API Google OSV en utilisant l'endpoint /v1/querybatch avec découpage par lots."""
    queries = [
        {"version": p["version"], "package": {"name": p["name"], "ecosystem": p.get("ecosystem", "PyPI")}}
        for p in packages if p.get("name") and p.get("version")
    ]
    all_results = []
    for i in range(0, len(queries), 100):
        chunk = {"queries": queries[i:i + 100]}
        try:
            resp = requests.post("https://api.osv.dev/v1/querybatch", json=chunk, timeout=15)
            if resp.status_code == 200:
                all_results.extend(resp.json().get("results", []))
            else:
                all_results.extend([{}] * len(chunk["queries"]))
        except Exception:
            all_results.extend([{}] * len(chunk["queries"]))
    return queries, all_results

@app.post("/api/inventory/", status_code=200)
def receive_inventory(inventory: InventoryEntry):
    total_vulns = 0
    queries, results = check_osv_vulnerabilities_batch(inventory.packages)
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        for i, result in enumerate(results):
            if "vulns" not in result:
                continue
            vulns   = [v.get("id") for v in result["vulns"]]
            total_vulns += len(vulns)
            name    = queries[i]["package"]["name"]
            version = queries[i]["version"]
            eco     = queries[i]["package"]["ecosystem"]
            ids_str = ", ".join(vulns[:3])
            msg     = f"Vulnérabilité ({eco}) : {name} v{version} → {ids_str}"

            cur.execute(
                "SELECT id FROM alerts WHERE hostname=%s AND alert_message=%s",
                (inventory.hostname, msg),
            )
            if cur.fetchone():
                continue

            cur.execute("""
                INSERT INTO alerts
                    (hostname, process_name, pid, port, alert_message,
                     is_anomaly, severity, risk_score, remediation_action)
                VALUES (%s,'Vulnerability-Scanner',0,0,%s,TRUE,'HIGH',70,%s)
            """, (inventory.hostname, msg, "Mettre à jour via apt/pip/npm"))

            logger.info(json.dumps({
                "soc_timestamp":        datetime.datetime.utcnow().isoformat(),
                "soc_hostname":         inventory.hostname,
                "soc_alert_message":    msg,
                "soc_is_anomaly":       True,
                "soc_severity":         "HIGH",
                "soc_remediation_action": "Mettre à jour le composant",
                "soc_source":           "osquery_vulnerability_scanner",
            }))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"status": "success", "vulnerabilities": total_vulns}


@app.get("/api/alerts/")
def get_alerts(limit: int = 100):
    """Retourne les alertes"""
    try:
        conn = get_db_connection()
        cur  = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT * FROM alerts WHERE resolved = FALSE ORDER BY timestamp DESC LIMIT %s", (limit,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.patch("/api/alerts/{alert_identifier}/resolve")
def resolve_alert(alert_identifier: str):
    """Marks an alert as resolved in the database so it leaves the active SOC queue."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # We try to resolve by ID if it's an integer, or fallback to PID if the ID wasn't available
        if alert_identifier.isdigit():
            cur.execute("""
                UPDATE alerts 
                SET resolved = TRUE 
                WHERE id = %s OR pid = %s
            """, (int(alert_identifier), int(alert_identifier)))
        else:
            cur.execute("UPDATE alerts SET resolved = TRUE WHERE id::text = %s", (alert_identifier,))
            
        conn.commit()
        cur.close()
        conn.close()
        
        return {"status": "success", "message": "Alerte acquittée"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/api/stats/")
def get_stats():
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE is_anomaly = TRUE")
        anomalies = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT hostname) FROM alerts")
        hosts = cur.fetchone()[0]
        cur.execute(
            "SELECT COUNT(*) FROM alerts WHERE is_anomaly=TRUE AND resolved=FALSE"
        )
        open_threats = cur.fetchone()[0]
        cur.close()
        conn.close()
        return {
            "total_alerts":  total,
            "anomalies":     anomalies,
            "unique_hosts":  hosts,
            "open_threats":  open_threats,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
       

@app.get("/health")
def health():
    return {
        "status":         "ok",
        "ml_trained":     detector.is_trained,
        "wazuh_api":      bool(WAZUH_API_URL),
        "wazuh_syslog":   bool(WAZUH_SYSLOG_HOST),
        "syslog_target":  f"{WAZUH_SYSLOG_HOST}:{WAZUH_SYSLOG_PORT}" if WAZUH_SYSLOG_HOST else "disabled",
    }

