# SOC Cyber-Detector - SIEM & ML Anomaly Detection

Ce projet implémente un Security Operations Center (SOC) open-source capable de détecter des exfiltrations et anomalies via Machine Learning.

## Architecture

1. **Agent Osquery (`osquery_agent.py`)** : Collecte les logs système (processus, ports, historique SQL).
2. **Backend FastAPI (`app.py`)** : Reçoit les logs, utilise `scikit-learn` (Machine Learning) pour détecter les anomalies (Isolation Forest), stocke en base et notifie Wazuh.
3. **Frontend (`index.html`, `style.css`, `script.js`)** : Dashboard d'alertes SIEM interactif pour la remédiation.

## Scénario de déploiement (4 VMs)

- **VM 1** : `nc -lvnp 4444` (Simulation Metasploit/Exfiltration).
- **VM 2** : `nc -lvnp 8080` (Usage non standard d'un port).
- **VM 3** : Exécution de requêtes SQL suspectes `SELECT * FROM users; DROP TABLE logs;`.
- **VM 4** : Exécution de requêtes SQL massives (exfiltration de données).
- **PC Principal** : Héberge le backend FastAPI, la base de données PostgreSQL, l'API Wazuh et le Frontend.

## Lancement

1. **Backend** :
   ```bash
   pip install -r requirements.txt
   uvicorn main:app --host 0.0.0.0 --port 8000
   ```
