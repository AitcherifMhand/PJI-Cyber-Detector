import subprocess
import json
import sys

def execute_osquery(query):
    """
    Exécute une requête SQL via osqueryi et retourne le résultat sous forme de dictionnaire Python.
    """
    try:
        # Appel de l'exécutable osqueryi en forçant le format de sortie en JSON
        result = subprocess.run(
            ['osqueryi', '--json', query],
            capture_output=True,
            text=True,
            check=True
        )
        # Conversion de la sortie texte JSON en liste/dictionnaire Python
        return json.loads(result.stdout)
    
    except subprocess.CalledProcessError as e:
        print(f"[Erreur Critique] L'exécution d'osquery a échoué : {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[Erreur] Impossible de décoder la réponse JSON d'osquery.")
        sys.exit(1)

def agent_routine():
    """
    Logique principale de l'agent : Analyse les ports en écoute et génère des alertes.
    """
    print("[*] Démarrage de l'agent de surveillance osquery...")

    # Requête SQL pour lister les processus en écoute.
    sql_query = """
        SELECT p.name, p.pid, l.port, l.address
        FROM listening_ports l
        JOIN processes p ON l.pid = p.pid
        WHERE l.port != 0;
    """

    print("[*] Collecte des données système en cours...")
    data = execute_osquery(sql_query)

    # Liste des ports que l'agent doit surveiller spécifiquement
    sensitive_ports = {
        22: "SSH", 
        3306: "MySQL", 
        8080: "HTTP Alternatif",
        4444: "Port suspect (Metasploit par défaut)"
    }

    alerts = []

    # Analyse des résultats
    for row in data:
        port = int(row.get('port', 0))
        process_name = row.get('name', 'Inconnu')
        pid = row.get('pid', 'N/A')

        if port in sensitive_ports:
            alerts.append(f"Le processus '{process_name}' (PID: {pid}) écoute sur le port {port} ({sensitive_ports[port]}).")

    # Génération du rapport / Actions de l'agent
    if alerts:
        print("\n[!] ANOMALIES DÉTECTÉES PAR L'AGENT :")
        for alert in alerts:
            print(f"  -> {alert}")
        print("\n[*] Action requise : Dans une version de production, l'agent enverrait ces logs à un SIEM ou un Webhook Slack.")
    else:
        print("\n[OK] Vérification terminée : Aucun port sensible n'est actuellement ouvert.")

if __name__ == "__main__":
    agent_routine()