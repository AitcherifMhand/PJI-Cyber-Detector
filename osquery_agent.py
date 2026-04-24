import subprocess
import json
import sys
import requests

# Configuration
API_URL = "http://localhost:8000/api/alerts/"

def execute_osquery(query):
    """
    Exécute une requête SQL via osqueryi et retourne le résultat sous forme de dictionnaire Python.
    """
    try:
        result = subprocess.run(
            ['osqueryi', '--json', query],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    
    except subprocess.CalledProcessError as e:
        print(f"[Erreur Critique] L'exécution d'osquery a échoué : {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[Erreur] Impossible de décoder la réponse JSON d'osquery.")
        sys.exit(1)

def send_alert_to_backend(process_name, pid, port, alert_message):
    """
    Envoie l'alerte formatée au backend FastAPI via une requête POST.
    """
    payload = {
        "process_name": str(process_name),
        "pid": str(pid),
        "port": int(port),
        "alert_message": alert_message
    }
    
    try:
        # Timeout de 5s pour éviter de bloquer l'agent si le backend est injoignable
        response = requests.post(API_URL, json=payload, timeout=5)
        
        if response.status_code == 201:
            print(f"  [+] Alerte transmise avec succès à l'API (Port: {port}).")
        else:
            print(f"  [-] Échec de la transmission. Code HTTP: {response.status_code} - Détail: {response.text}")
            
    except requests.exceptions.RequestException as e:
        print(f"  [!] Impossible de joindre le backend API : {e}")

def agent_routine():
    """
    Logique principale de l'agent : Analyse les ports en écoute et génère des alertes.
    """
    print("[*] Démarrage de l'agent de surveillance osquery...")

    sql_query = """
        SELECT p.name, p.pid, l.port, l.address
        FROM listening_ports l
        JOIN processes p ON l.pid = p.pid
        WHERE l.port != 0;
    """

    print("[*] Collecte des données système en cours...")
    data = execute_osquery(sql_query)

    sensitive_ports = {
        22: "SSH", 
        3306: "MySQL", 
        8080: "HTTP Alternatif",
        4444: "Port suspect (Metasploit par défaut)"
    }

    alerts_count = 0

    # Analyse des résultats
    for row in data:
        port = int(row.get('port', 0))
        process_name = row.get('name', 'Inconnu')
        pid = row.get('pid', 'N/A')

        if port in sensitive_ports:
            alert_msg = f"Le processus '{process_name}' écoute sur un port sensible ({sensitive_ports[port]})."
            print(f"\n[!] ANOMALIE DÉTECTÉE : {process_name} (PID: {pid}) sur le port {port}")
            
            # Envoi automatique de l'alerte à la base de données via l'API
            send_alert_to_backend(process_name, pid, port, alert_msg)
            alerts_count += 1

    if alerts_count == 0:
        print("\n[OK] Vérification terminée : Aucun port sensible n'est actuellement ouvert.")
    else:
        print(f"\n[*] Fin de l'analyse. {alerts_count} alerte(s) générée(s) et envoyée(s).")

if __name__ == "__main__":
    agent_routine()