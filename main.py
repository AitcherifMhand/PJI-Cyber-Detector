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
#from ml_module import CyberAnomalyDetector
from typing import Optional
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
log_file_path = 'soc_alerts.json'
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
                pid INTEGER,
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

def check_osv_vulnerabilities_batch(packages):
    """Interroge l'API Google OSV en utilisant l'endpoint /v1/querybatch avec découpage par lots."""
    url = "https://api.osv.dev/v1/querybatch"
    queries = []
    for pkg in packages:
        if pkg.get("name") and pkg.get("version"):
            queries.append({
                "version": pkg.get("version"),
                "package": {
                    "name": pkg.get("name"),
                    "ecosystem": pkg.get("ecosystem", "PyPI")
                }
            })
            
    all_results = []
    chunk_size = 100
    
    for i in range(0, len(queries), chunk_size):
        chunk = {"queries": queries[i:i + chunk_size]}
        try:
            resp = requests.post(url, json=chunk, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                all_results.extend(data.get("results", []))
            else:
                logger.error(f"[ERREUR] API OSV HTTP {resp.status_code}")
                all_results.extend([{} for _ in range(len(chunk["queries"]))])
        except Exception as e:
            logger.error(f"[ERREUR] Exception OSV API: {e}")
            all_results.extend([{} for _ in range(len(chunk["queries"]))])
            
    return queries, all_results

@app.post("/api/inventory/", status_code=200)
def receive_inventory(inventory: InventoryEntry):
    total_vulns = 0
    conn = get_db_connection()
    cursor = conn.cursor()

    queries, results = check_osv_vulnerabilities_batch(inventory.packages)

    for i, result in enumerate(results):
        if "vulns" in result:
            vulns = [v.get("id") for v in result["vulns"]]
            total_vulns += len(vulns)
            
            name = queries[i]["package"]["name"]
            version = queries[i]["version"]
            ecosystem = queries[i]["package"]["ecosystem"]
            
            vuln_list = ", ".join(vulns[:3]) 
            msg = f"Alerte Vulnérabilité ({ecosystem}) : {name} v{version} est vulnérable ({vuln_list})"
            cursor.execute("SELECT id FROM alerts WHERE hostname=%s AND alert_message=%s", (inventory.hostname, msg))
            if cursor.fetchone():
                continue
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

def get_wazuh_alerts(token, limit=100):
    url = f"{WAZUH_API_URL}/alerts/history?limit={limit}"
    headers = {"Authorization": f"Bearer {token}"}    
    resp = requests.get(url, headers=headers, verify=False) 
    if resp.status_code == 200:
        return resp.json()['data']['affected_items']
    return []

@app.get("/api/alerts/")
def get_alerts(limit: int = 100):
    try:
        token = get_wazuh_token()
        wazuh_alerts = get_wazuh_alerts(token, limit)
        formatted_alerts = []
        for alert in wazuh_alerts:
            original_log = alert.get('data', {}) 
            
            formatted_alerts.append({
                "id": alert.get('id'),
                "timestamp": alert.get('timestamp'),
                "hostname": alert.get('agent', {}).get('name', 'Unknown'),
                "process_name": original_log.get('process_name', 'Unknown'),
                "pid": original_log.get('pid', '0'),
                "port": original_log.get('port', 0),
                "alert_message": alert.get('rule', {}).get('description', 'Unknown Alert'),
                "is_anomaly": original_log.get('is_anomaly', False),
                "remediation_action": original_log.get('remediation_action', ''),
                "rule_level": alert.get('rule', {}).get('level', 0)
            })
        return formatted_alerts

    except Exception as e:
        print(f"Error fetching from Wazuh: {e}. Falling back to DB.")
        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=RealDictCursor) 
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT %s", (limit,))
            rows = cursor.fetchall()
            cursor.close()
            conn.close()
            return rows
        except Exception as db_e:
            raise HTTPException(status_code=500, detail=str(db_e))

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
def request_kill_process(pid: int, hostname: str = ""):
    try:
        token = get_wazuh_token()
        agent_id = get_agent_id(hostname, token)
        
        if not agent_id:
            logger.warning(f"[WAZUH] Agent introuvable pour {hostname}. Remédiation ignorée.")
            return {"status": "failed", "message": f"Agent Wazuh introuvable pour {hostname}"}

        ar_url = f"{WAZUH_API_URL}/active-response?agents_list={agent_id}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "command": "custom-kill",
            "custom": True,
            "arguments": [str(pid)] 
        }
        resp = requests.put(ar_url, headers=headers, json=payload, verify=False, timeout=5)
        if resp.status_code == 200:
            return {"status": "success", "message": f"Active response envoyée à l'agent {agent_id}"}
        else:
            logger.error(f"[WAZUH] Erreur Active Response (HTTP {resp.status_code}): {resp.text}")
            return {"status": "failed", "message": f"Wazuh a refusé l'ordre (Erreur {resp.status_code})"}
            
    except requests.exceptions.RequestException as e:
        logger.error(f"[WAZUH] Impossible de joindre le serveur Wazuh : {e}")
        return {"status": "failed", "message": "Le serveur Wazuh est actuellement injoignable."}
    except Exception as e:
        logger.error(f"[WAZUH] Exception inattendue lors de la remédiation : {e}")
        return {"status": "failed", "message": "Erreur interne lors de la communication avec Wazuh."}
    
@app.get("/api/actions/pending")
def get_pending_actions():
    """L'agent Osquery interrogera cette route pour savoir s'il doit agir."""
    actions = pending_actions.copy()
    pending_actions.clear() # Vider la file une fois récupérée par l'agent
    return actions
