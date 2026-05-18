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
from typing import Optional
app = FastAPI(title="SOC Cyber-Detector API", description="API avec PostgreSQL")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
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
except KeyError as e:
    print(f"[ERREUR] Configuration Wazuh manquante dans wazuh.config: {e}")
log_file_path = '/var/log/soc_alerts.json'
logger = logging.getLogger("SOC_Logger")
logger.setLevel(logging.INFO)
handler = logging.FileHandler(log_file_path)
formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)
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
            datetime.datetime.now(), log.hostname, log.process_name, log.pid, log.port, log.alert_message, is_anomaly, remediation
        ))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PostgreSQL Error: {str(e)}")

    # Enregistrement dans le fichier JSON (Pour ingestion par Wazuh)
    log_dict = log.dict()
    log_dict["timestamp"] = datetime.datetime.utcnow().isoformat()
    log_dict["is_anomaly"] = is_anomaly
    log_dict["remediation_action"] = remediation
    log_dict["soc_source"] = "osquery_agent"
    
    logger.info(json.dumps(log_dict))

    return {"status": "success", "is_anomaly": is_anomaly, "remediation": remediation}

def check_osv_vulnerability(package_name, version, ecosystem):
    """Interroge l'API Google OSV pour trouver des CVE sur un package spécifique."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": ecosystem 
        }
    }
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if "vulns" in data:
                return [vuln.get("id") for vuln in data["vulns"]]
    except Exception as e:
        print(f"[ERREUR] API OSV ({package_name}) : {e}")
    return []

@app.post("/api/inventory/", status_code=200)
def receive_inventory(inventory: InventoryEntry):
    total_vulns = 0
    conn = get_db_connection()
    cursor = conn.cursor()

    for pkg in inventory.packages:
        name = pkg.get("name")
        version = pkg.get("version")
        ecosystem = pkg.get("ecosystem", "PyPI") # Valeur par défaut si non fourni

        if not name or not version:
            continue

        vulns = check_osv_vulnerability(name, version, ecosystem)

        if vulns:
            total_vulns += len(vulns)
            vuln_list = ", ".join(vulns[:3]) 
            msg = f"Alerte Vulnérabilité ({ecosystem}) : {name} v{version} est vulnérable ({vuln_list})"

            cursor.execute('''
                INSERT INTO alerts (timestamp, hostname, process_name, pid, port, alert_message, is_anomaly, remediation_action)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                datetime.datetime.now(), inventory.hostname, "Vulnerability-Scanner", "0", 0, msg, True, "Mettre à jour via apt/pip/npm"
            ))

            log_dict = {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "hostname": inventory.hostname,
                "alert_message": msg,
                "is_anomaly": True,
                "remediation_action": "Mettre à jour le composant système",
                "soc_source": "osquery_vulnerability_scanner"
            }
            logger.info(json.dumps(log_dict))

    conn.commit()
    cursor.close()
    conn.close()

    return {"status": "success", "vulnerabilities": total_vulns}

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
    
def get_wazuh_token():
    auth_url = f"{WAZUH_API_URL}/security/user/authenticate"
    resp = requests.post(auth_url, auth=(WAZUH_API_USER, WAZUH_API_PASS), verify=False)
    if resp.status_code == 200:
        return resp.json()['data']['token']
    raise Exception("Failed to authenticate with Wazuh API")

def get_agent_id(hostname, token):
    url = f"{WAZUH_API_URL}/agents?q=name={hostname}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, verify=False)
    if resp.status_code == 200 and resp.json()['data']['affected_items']:
        return resp.json()['data']['affected_items'][0]['id']
    return None

@app.post("/api/actions/kill/{pid}", status_code=200)
def request_kill_process(pid: str, hostname: str = ""):
    """Déclenche la remédiation Wazuh (Active Response) au lieu de mettre en file d'attente."""
    try:
        token = get_wazuh_token()
        agent_id = get_agent_id(hostname, token)
        
        if not agent_id:
            raise HTTPException(status_code=404, detail=f"Wazuh Agent introuvable pour {hostname}")

        # Déclenchement de l'Active Response
        ar_url = f"{WAZUH_API_URL}/active-response?agents_list={agent_id}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "command": "custom-kill",
            "custom": True,
            "arguments": [pid]
        }
        
        resp = requests.put(ar_url, headers=headers, json=payload, verify=False)
        if resp.status_code == 200:
            return {"status": "success", "message": f"Active response envoyée à l'agent {agent_id}"}
        else:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
            
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))
@app.get("/api/actions/pending")
def get_pending_actions():
    """L'agent Osquery interrogera cette route pour savoir s'il doit agir."""
    actions = pending_actions.copy()
    pending_actions.clear() # Vider la file une fois récupérée par l'agent
    return actions