import subprocess
import json
import sys
import time
import requests
import socket
import argparse
import os
from dotenv import load_dotenv

load_dotenv()

DB_LOG_FILE =os.getenv("DB_LOG_FILE", "")

API_URL = ""
HOSTNAME = ""

SENSITIVE_PORTS = {
    22: "SSH",
    3306: "MySQL",
    8080: "HTTP Alternatif",
    4444: "Port suspect "
}

SUSPICIOUS_PROCESSES = ["nc", "ncat", "netcat", "msfconsole", "python3", "bash"]

SQL_KEYWORDS = ["SELECT", "INSERT", "DROP", "UPDATE", "DELETE"]

SEEN_ALERTS = set()
LOG_POINTERS = {}

def execute_osquery(query):
    try:
        result = subprocess.run(
            ['osqueryi', '--json', query],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        print("[Erreur] osquery timeout.")
        return []
    except json.JSONDecodeError:
        print("[Erreur] Réponse JSON invalide.")
        return []

def send_log(process_name, pid, port, message, bytes_sent=0, query_text=""):
    """Envoie un log au backend."""
    payload = {
        "hostname": HOSTNAME,
        "process_name": str(process_name),
        "pid": int(pid),
        "port": int(port),
        "alert_message": message,
        "bytes_sent": bytes_sent,
        "query_text": query_text
    }
    try:
        r = requests.post(f"{API_URL}/logs/", json=payload, timeout=5)
        if r.status_code == 201:
            resp = r.json()
            print(f"  [+] Log envoyé → anomalie={resp.get('is_anomaly')}, remédiation={resp.get('remediation')}")
        else:
            print(f"  [-] Erreur HTTP {r.status_code}")
    except Exception as e:
        print(f"  [!] Backend inaccessible : {e}")
def init_log_pointers():
    """Initialise le pointeur à la fin du fichier pour ne pas lire le passé."""
    if os.path.exists(DB_LOG_FILE):
        LOG_POINTERS[DB_LOG_FILE] = os.path.getsize(DB_LOG_FILE)
        print(f"[*] Suivi du log BDD initialisé ({LOG_POINTERS[DB_LOG_FILE]} octets passés).")
    else:
        print(f"[!] Fichier de log BDD introuvable : {DB_LOG_FILE}")
        LOG_POINTERS[DB_LOG_FILE] = 0

def check_db_logs():
    """ Lit incrémentalement le fichier de log de la base de données."""
    if not os.path.exists(DB_LOG_FILE):
        return

    current_pointer = LOG_POINTERS.get(DB_LOG_FILE, 0)
    current_size = os.path.getsize(DB_LOG_FILE)

    if current_size < current_pointer:
        current_pointer = 0

    if current_pointer == current_size:
        return # Rien de nouveau à lire

    try:
        with open(DB_LOG_FILE, 'r') as f:
            f.seek(current_pointer)
            new_lines = f.readlines()
            # Mettre à jour le pointeur pour le prochain cycle
            LOG_POINTERS[DB_LOG_FILE] = f.tell()

            for line in new_lines:
                # Filtrage simple (à adapter selon le format exact de tes logs)
                line_upper = line.upper()
                if "FATAL" in line_upper or "ERROR" in line_upper or any(kw in line_upper for kw in SQL_KEYWORDS):
                    msg = f"Activité BDD suspecte : {line.strip()[:150]}..."
                    print(f"[!] LOG BDD DETECTE : {msg}")
                    # Envoi au backend (on attribue un faux PID pour la forme)
                    send_log("postgres_daemon", 0, 5432, msg, query_text=line.strip())

    except Exception as e:
        print(f"[Erreur] Lecture du log BDD impossible : {e}")
def check_ports():
    """Cas d'usage 1 - Ports sensibles en écoute (Dédoublonné)."""
    query = """
        SELECT p.name, p.pid, l.port, l.address
        FROM listening_ports l
        JOIN processes p ON l.pid = p.pid
        WHERE l.port != 0
    """
    for row in execute_osquery(query):
        port = int(row.get('port', 0))
        if port in SENSITIVE_PORTS:
            name = row.get('name', 'inconnu')
            pid = row.get('pid', 0)            
            alert_key = f"port_{pid}_{port}"
            if alert_key not in SEEN_ALERTS:
                msg = f"Processus {name} (PID {pid}) écoute sur le port sensible {port} ({SENSITIVE_PORTS[port]})"
                print(f"[!] PORT SUSPECT : {msg}")
                send_log(name, pid, port, msg)
                SEEN_ALERTS.add(alert_key)

def check_suspicious_processes():
    """Cas d'usage 1 — processus suspects lancés (Dédoublonné)."""
    data = execute_osquery("""
        SELECT name, pid, cmdline
        FROM processes
        WHERE name IN ('nc', 'ncat', 'netcat', 'msfconsole');
    """)
    for row in data:
        name = row.get('name', 'inconnu')
        pid = row.get('pid', '0')
        cmdline = row.get('cmdline', '')
        alert_key = f"proc_{pid}_{name}"
        if alert_key not in SEEN_ALERTS:
            msg = f"Processus suspect détecté : '{name}' (cmdline: {cmdline})."
            print(f"[!] PROCESSUS SUSPECT : {name} (PID {pid})")
            send_log(name, pid, 0, msg)
            SEEN_ALERTS.add(alert_key)

def check_shell_history_for_sql():
    """Cas d'usage 2 & 3 — détection SQL ET Exfiltration (curl/wget)."""
    data = execute_osquery("""
        SELECT uid, command, history_file
        FROM shell_history
        WHERE command LIKE '%SELECT%'
           OR command LIKE '%INSERT%'
           OR command LIKE '%DROP%'
           OR command LIKE '%DELETE%'
           OR command LIKE '%curl%'
           OR command LIKE '%wget%'
        LIMIT 50;
    """)
    for row in data:
        cmd = row.get('command', '')
        uid = row.get('uid', '0')        
        alert_key = f"hist_{uid}_{cmd}"
        if alert_key not in SEEN_ALERTS:
            msg = f"Commande suspecte dans l'historique (uid {uid}): {cmd[:100]}"
            print(f"[!] HISTORIQUE SUSPECT : {cmd[:60]}...")
            send_log("shell", uid, 0, msg)
            SEEN_ALERTS.add(alert_key)
def check_network_traffic():
    """Surveillance basique du trafic réseau via netstat ou osquery (socket_events requis)."""
    query = """
        SELECT s.pid, p.name, SUM(s.bytes_sent) as total_bytes
        FROM socket_events s
        JOIN processes p ON s.pid = p.pid
        WHERE s.bytes_sent > 0
        GROUP BY s.pid, p.name
        HAVING SUM(s.bytes_sent) > 10000000
    """
    for row in execute_osquery(query):
        pid = row.get('pid', 0)
        name = row.get('name', 'inconnu')
        total_bytes = row.get('total_bytes', 0)
        msg = f"Trafic réseau élevé : {total_bytes} octets envoyés par {name} (PID {pid})"
        print(f"[!] TRAFIC ANORMAL : {msg}")
        send_log(name, pid, 0, msg, bytes_sent=total_bytes)  
         
def check_software_inventory():
    """Vérification des dépendances """
    all_packages = []

    os_info = execute_osquery("SELECT platform_like, name FROM os_version;")
    platform_like = os_info[0].get("platform_like", "").lower() if os_info else ""
    
    # Collecte des paquets Système selon l'OS détecté
    if "debian" in platform_like or "ubuntu" in platform_like:
        os_data = execute_osquery("SELECT name, version FROM deb_packages;")
        ecosystem = "Debian"
    elif "rhel" in platform_like or "centos" in platform_like or "fedora" in platform_like:
        os_data = execute_osquery("SELECT name, version FROM rpm_packages;")
        ecosystem = "RedHat" 
    else:
        os_data = []
        ecosystem = "Unknown"

    for row in os_data:
        all_packages.append({"name": row["name"], "version": row["version"], "ecosystem": ecosystem})

    # Paquets Python 
    py_data = execute_osquery("SELECT name, version FROM python_packages;")
    for row in py_data:
        all_packages.append({"name": row["name"], "version": row["version"], "ecosystem": "PyPI"})
    # Paquets Node.js
    npm_data = execute_osquery("SELECT name, version FROM npm_packages;")
    for row in npm_data:
        all_packages.append({"name": row["name"], "version": row["version"], "ecosystem": "npm"})
    if not all_packages:
        return

    payload = {
        "hostname": HOSTNAME,
        "packages": all_packages
    }

    try:
        r = requests.post(f"{API_URL}/inventory/", json=payload, timeout=15)
        if r.status_code == 200:
            resp = r.json()
            vulns = resp.get("vulnerabilities", 0)
            if vulns > 0:
                print(f"[!] INVENTAIRE GLOBAL : {vulns} vulnérabilité(s) trouvée(s) sur le serveur !")
            else:
                print(f"  [+] Inventaire système ({ecosystem}) vérifié (0 vulnérabilité).")
    except Exception as e:
        print(f"  [!] Backend inaccessible pour l'inventaire : {e}")  
                        
def agent_loop(interval_seconds=30):
    print(f"[*] Agent SOC démarré — cycle toutes les {interval_seconds}s.")
    cycle_count = 0
    while True:
        cycle_count += 1
        print(f"\n[*] --- Cycle {time.strftime('%H:%M:%S')} ---")
        check_ports()
        check_suspicious_processes()
        check_shell_history_for_sql()
        check_network_traffic()
        check_db_logs()
        # L'inventaire logiciel change peu, on le lance 1 fois sur 10 cycles
        if cycle_count % 10 == 1:
            print("[*] Lancement de l'analyse d'inventaire logiciel (Supply Chain)...")
            check_software_inventory()
        print(f"[*] Prochain cycle dans {interval_seconds}s...")
        time.sleep(interval_seconds)

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Agent de détection osquery pour le SOC")   
    parser.add_argument(
        "--api-url", 
        type=str, 
        default="http://localhost:8000/api", 
        help="URL de base de l'API (défaut: http://localhost:8000/api/alerts/)"
    )   
    parser.add_argument(
        "--hostname", 
        type=str, 
        default=socket.gethostname(), 
        help=f"Nom d'hôte identifiant cet agent (défaut: {socket.gethostname()})"
    ) 
    parser.add_argument(
        "--interval", 
        type=int, 
        default=30, 
        help="Intervalle entre chaque vérification en secondes (défaut: 30)"
    )
    args = parser.parse_args()

    API_URL = args.api_url
    HOSTNAME = args.hostname

    print(f"[*] Configuration : API={API_URL} | HOST={HOSTNAME} | INTERVALLE={args.interval}s")

    try:
        agent_loop(interval_seconds=args.interval)
    except KeyboardInterrupt:
        print("\n[*] Agent arrêté.")