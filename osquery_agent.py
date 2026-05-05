import subprocess
import json
import sys
import time
import requests

# Configuration
API_URL = "http://localhost:8000/api/alerts/"

SENSITIVE_PORTS = {
    22: "SSH",
    3306: "MySQL",
    8080: "HTTP Alternatif",
    4444: "Port suspect "
}

SUSPICIOUS_PROCESSES = ["nc", "ncat", "netcat", "msfconsole", "python3", "bash"]

SQL_KEYWORDS = ["SELECT", "INSERT", "DROP", "UPDATE", "DELETE"]

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

def send_alert(process_name, pid, port, message):
    payload = {
        "process_name": str(process_name),
        "pid": str(pid),
        "port": int(port),
        "alert_message": message
    }
    try:
        r = requests.post(API_URL, json=payload, timeout=5)
        if r.status_code == 201:
            print(f"  [+] Alerte envoyée (port {port}, {process_name})")
        else:
            print(f"  [-] Échec envoi : {r.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  [!] Backend inaccessible : {e}")

def check_ports():
    """Cas d'usage 1 — ports sensibles en écoute."""
    data = execute_osquery("""
        SELECT p.name, p.pid, l.port
        FROM listening_ports l
        JOIN processes p ON l.pid = p.pid
        WHERE l.port != 0;
    """)
    for row in data:
        port = int(row.get('port', 0))
        if port in SENSITIVE_PORTS:
            name = row.get('name', 'inconnu')
            pid = row.get('pid', '0')
            msg = f"Processus '{name}' en écoute sur port sensible ({SENSITIVE_PORTS[port]})."
            print(f"[!] PORT SENSIBLE : {name} (PID {pid}) → :{port}")
            send_alert(name, pid, port, msg)

def check_suspicious_processes():
    """Cas d'usage 1 — processus suspects lancés."""
    data = execute_osquery("""
        SELECT name, pid, cmdline
        FROM processes
        WHERE name IN ('nc', 'ncat', 'netcat', 'msfconsole');
    """)
    for row in data:
        name = row.get('name', 'inconnu')
        pid = row.get('pid', '0')
        cmdline = row.get('cmdline', '')
        msg = f"Processus suspect détecté : '{name}' (cmdline: {cmdline})."
        print(f"[!] PROCESSUS SUSPECT : {name} (PID {pid})")
        send_alert(name, pid, 0, msg)

def check_shell_history_for_sql():
    """Cas d'usage 2 — détection de commandes SQL dans l'historique shell."""
    data = execute_osquery("""
        SELECT uid, command, history_file
        FROM shell_history
        WHERE command LIKE '%SELECT%'
           OR command LIKE '%INSERT%'
           OR command LIKE '%DROP%'
           OR command LIKE '%DELETE%'
        LIMIT 50;
    """)
    for row in data:
        cmd = row.get('command', '')
        uid = row.get('uid', '0')
        msg = f"Instruction SQL détectée dans l'historique shell (uid {uid}): {cmd[:100]}"
        print(f"[!] SQL SHELL HISTORY : {cmd[:60]}...")
        send_alert("shell", uid, 0, msg)
        
def fetch_and_execute_actions():
    """Interroge le backend pour voir si l'admin a cliqué sur le bouton Kill."""
    try:
        r = requests.get(f"{API_URL.replace('alerts/', 'actions/pending')}", timeout=5)
        if r.status_code == 200:
            actions = r.json()
            for action in actions:
                if action.get("action") == "kill":
                    pid_to_kill = action.get("pid")
                    print(f"[*] ORDRE REÇU DU BACKEND : Tuer le PID {pid_to_kill}")
                    execute_kill(pid_to_kill)
    except requests.exceptions.RequestException:
        pass

def execute_kill(pid):
    """Exécute la commande système pour tuer le processus."""
    try:
        # Tente de tuer le processus proprement, puis par la force
        subprocess.run(['kill', '-9', str(pid)], capture_output=True, text=True)
        print(f"  [+] PID {pid} terminé avec succès.")
    except Exception as e:
        print(f"  [-] Échec lors de la destruction du PID {pid}: {e}")
def agent_loop(interval_seconds=30):
    print(f"[*] Agent SOC démarré — cycle toutes les {interval_seconds}s.")
    while True:
        print(f"\n[*] --- Cycle {time.strftime('%H:%M:%S')} ---")
        check_ports()
        check_suspicious_processes()
        check_shell_history_for_sql()
        print(f"[*] Prochain cycle dans {interval_seconds}s...")
        fetch_and_execute_actions()
        time.sleep(interval_seconds)

if __name__ == "__main__":
    try:
        agent_loop(interval_seconds=30)
    except KeyboardInterrupt:
        print("\n[*] Agent arrêté.")