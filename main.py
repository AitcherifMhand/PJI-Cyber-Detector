from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
import datetime
import configparser
import logging
import json
import requests
import os
from ml_module import CyberAnomalyDetector
from typing import Optional
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Chargement du modèle ML

ML_MODEL_PATH = os.environ.get("ML_MODEL_PATH", "ml/ml_behavioral_model.joblib")
detector = CyberAnomalyDetector.load_model(ML_MODEL_PATH)

app = FastAPI(title="SOC Cyber-Detector API", description="API avec PostgreSQL")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# --- WAZUH CONFIGURATION ---
wazuh_config = configparser.ConfigParser()
wazuh_config.read('wazuh.config')
try:
    WAZUH_API_URL = wazuh_config['wazuh']['url']
    WAZUH_API_USER = wazuh_config['wazuh']['user']
    WAZUH_API_PASS = wazuh_config['wazuh']['password']
    WAZUH_VERIFY_TLS = wazuh_config["wazuh"].getboolean("verify_tls", fallback=False)

except KeyError as e:
    print(f"[ERREUR] Configuration Wazuh manquante dans wazuh.config: {e}")
    WAZUH_API_URL = WAZUH_API_USER = WAZUH_API_PASS = ""
    WAZUH_VERIFY_TLS = False

log_file_path = os.environ.get("SOC_LOG_PATH", "soc_alerts.json")
logger = logging.getLogger("SOC_Logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_file_path)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS pending_actions (
                id          SERIAL PRIMARY KEY,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hostname    VARCHAR(255),
                action      VARCHAR(64),
                pid         INTEGER,
                done        BOOLEAN DEFAULT FALSE
            )
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("[OK] Base de données PostgreSQL initialisée.")
    except Exception as e:
        print(f"[ERREUR] Impossible de se connecter à PostgreSQL : {e}")

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
        f"{WAZUH_API_URL}/alerts/history?limit={limit}",
        headers={"Authorization": f"Bearer {token}"},
        verify=WAZUH_VERIFY_TLS,
        timeout=10,
    )
    if resp.status_code == 200:
        return resp.json()["data"]["affected_items"]
    return []

@app.post("/api/logs/", status_code=201)
def receive_log(log: LogEntry):
    """Point d'entrée principal de l'agent Osquery."""

    # Horodatage de réception si absent
    log_dict = log.dict()
    if not log_dict.get("timestamp"):
        log_dict["timestamp"] = datetime.datetime.utcnow().isoformat()

    #  SCORING ML + RÈGLES 
    result      = detector.predict(log_dict)
    is_anomaly  = result["is_anomaly"]
    severity    = result["severity"]
    risk_score  = result["risk_score"]
    ml_score    = result["ml_score"]
    rules_score = result["rules_score"]
    remediation = result["remediation"]
    reasons     = " | ".join(result["reasons"]) if result["reasons"] else ""
    risk_axes   = json.dumps(result["risk_axes"])

    #  SAUVEGARDE BDD 
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO alerts
                (timestamp, hostname, process_name, pid, port, alert_message,
                 is_anomaly, severity, risk_score, ml_score, rules_score,
                 remediation_action, reasons, risk_axes, bytes_sent, remote_ip)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            log_dict["timestamp"], log.hostname, log.process_name, log.pid,
            log.port, log.alert_message, is_anomaly, severity, risk_score,
            ml_score, rules_score, remediation, reasons, risk_axes,
            log.bytes_sent or 0, log.remote_ip or "",
        ))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {e}")

    # Log JSON ==> Wazuh
    log_dict.update({
        "is_anomaly":        is_anomaly,
        "severity":          severity,
        "risk_score":        risk_score,
        "ml_score":          ml_score,
        "rules_score":       rules_score,
        "remediation_action": remediation,
        "reasons":           result["reasons"],
        "soc_source":        "osquery_agent",
    })
    logger.info(json.dumps(log_dict))

    return {
        "status":      "success",
        "is_anomaly":  is_anomaly,
        "severity":    severity,
        "risk_score":  risk_score,
        "remediation": remediation,
        "reasons":     result["reasons"],
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
                "timestamp":        datetime.datetime.utcnow().isoformat(),
                "hostname":         inventory.hostname,
                "alert_message":    msg,
                "is_anomaly":       True,
                "severity":         "HIGH",
                "remediation_action": "Mettre à jour le composant",
                "soc_source":       "osquery_vulnerability_scanner",
            }))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"status": "success", "vulnerabilities": total_vulns}


@app.get("/api/alerts/")
def get_alerts(limit: int = 100):
    """Retourne les alertes — Wazuh en priorité, BDD en fallback."""
    try:
        if WAZUH_API_URL:
            token = get_wazuh_token()
            wazuh_alerts = get_wazuh_alerts(token, limit)
            formatted = []
            for a in wazuh_alerts:
                d = a.get("data", {})
                formatted.append({
                    "id":               a.get("id"),
                    "timestamp":        a.get("timestamp"),
                    "hostname":         a.get("agent", {}).get("name", "Unknown"),
                    "process_name":     d.get("process_name", "Unknown"),
                    "pid":              d.get("pid", 0),
                    "port":             d.get("port", 0),
                    "alert_message":    a.get("rule", {}).get("description", ""),
                    "is_anomaly":       d.get("is_anomaly", False),
                    "severity":         d.get("severity", "INFO"),
                    "risk_score":       d.get("risk_score", 0),
                    "remediation_action": d.get("remediation_action", ""),
                    "resolved":         False,
                    "rule_level":       a.get("rule", {}).get("level", 0),
                })
            return formatted
    except Exception as e:
        print(f"[WARN] Wazuh inaccessible : {e} — fallback DB")

    # Fallback PostgreSQL
    try:
        conn = get_db_connection()
        cur  = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s", (limit,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()
        conn.close()
        return rows
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
       
    
@app.post("/api/actions/kill/{pid}", status_code=200)
def request_kill_process(pid: int, hostname: str = ""):
    try:
        conn = get_db_connection()
        cur  = conn.cursor()
        cur.execute(
            "INSERT INTO pending_actions (hostname, action, pid) VALUES (%s, %s, %s)",
            (hostname, "kill", pid),
        )
        # Marquer resolved dans alerts
        cur.execute(
            "UPDATE alerts SET resolved=TRUE WHERE pid=%s AND hostname=%s AND resolved=FALSE",
            (pid, hostname),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"[WARN] DB pending_actions : {e}")

    # Tentative Active Response Wazuh
    if WAZUH_API_URL:
        try:
            token    = get_wazuh_token()
            agent_id = get_agent_id(hostname, token)
            if not agent_id:
                return {"status": "queued", "message": f"Agent Wazuh introuvable pour {hostname} — ordre en file BDD"}

            resp = requests.put(
                f"{WAZUH_API_URL}/active-response?agents_list={agent_id}",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"command": "custom-kill", "custom": True, "arguments": [str(pid)]},
                verify=WAZUH_VERIFY_TLS,
                timeout=8,
            )
            if resp.status_code == 200:
                return {"status": "success", "message": f"Active Response envoyée à l'agent {agent_id}"}
            return {"status": "queued", "message": f"Wazuh refus ({resp.status_code}) — ordre en file BDD"}
        except Exception as e:
            print(f"[WARN] Wazuh AR : {e}")
            return {"status": "queued", "message": "Wazuh inaccessible — ordre en file BDD"}

    return {"status": "queued", "message": "Mode sans Wazuh — ordre en file BDD"}
    
@app.get("/api/actions/pending")
def get_pending_actions():
    """L'agent Osquery poll cette route pour récupérer ses ordres."""
    try:
        conn = get_db_connection()
        cur  = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT id, hostname, action, pid FROM pending_actions WHERE done=FALSE ORDER BY created_at"
        )
        actions = [dict(r) for r in cur.fetchall()]
        if actions:
            ids = [a["id"] for a in actions]
            cur.execute(
                f"UPDATE pending_actions SET done=TRUE WHERE id = ANY(%s)", (ids,)
            )
            conn.commit()
        cur.close()
        conn.close()
        return actions
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health():
    return {
        "status":     "ok",
        "ml_trained": detector.is_trained,
        "wazuh":      bool(WAZUH_API_URL),
    }