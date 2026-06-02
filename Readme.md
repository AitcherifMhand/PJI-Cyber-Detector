# SOC Cyber-Detector - SIEM & ML Anomaly Detection

Ce projet implémente un Security Operations Center (SOC) open-source capable de détecter des exfiltrations et anomalies via Machine Learning.

## Architecture

1. **L'Agent (`osquery_agent.py`)** : Tourne sur la machine à surveiller, interroge le système et envoie les logs au backend.
2. **Le Backend (`main.py`)** : Reçoit les logs, les analyse avec le modèle d'IA (`ml_module.py`) et les sauvegarde dans la base de données.
3. **La Base de données (PostgreSQL)** : Stocke l'historique brut et les alertes.
4. **Wazuh** : Le SIEM central qui reçoit les alertes critiques via Syslog.
5. **Le Dashboard (`index.html`)** : L'interface visuelle pour lire les alertes.

---

## **Étape 1 : Les Prérequis Système**


* **Python 3.10+**
* **PostgreSQL**
* **Osquery** 
* **Wazuh Manager** 

## **Étape 2 : Configuration des fichiers d'environnement**

Le backend utilise à la fois un fichier `.env` (pour les variables générales) et un fichier `db.config` (pour la base de données de l'IA). Créez ces deux fichiers à la racine de projet.

### **1. Le fichier .env**

Créez un fichier nommé exactement `.env` et copiez-y ceci, en adaptant les valeurs à votre environnement :

```env
# --- Base de données PostgreSQL ---
DB_NAME="soc_db"
DB_USER="postgres"
DB_PASSWORD="votre_mot_de_passe_sql"
DB_HOST="localhost"
DB_PORT="5432"

# --- Configuration Wazuh (API et Syslog) ---
WAZUH_API_URL="https://192.168.X.X:55000"
WAZUH_API_USER="wazuh-wui"
WAZUH_API_PASSWORD="votre_mot_de_passe_wazuh"
WAZUH_VERIFY_TLS="False"

# L'IP de votre serveur Wazuh pour recevoir les alertes ML
WAZUH_SYSLOG_HOST="192.168.X.X"
WAZUH_SYSLOG_PORT="514"

# --- Machine Learning & Logs ---
ML_MODEL_PATH="ml_behavioral_model.joblib"
SOC_LOG_PATH="soc_alerts.json"

# --- Agent Osquery ---
# Fichier de log spécifique d'une base de données à surveiller (ex: postgresql.log)
DB_LOG_FILE="/var/log/postgresql/postgresql-14-main.log"

```

### **2. Le fichier db.config**

Le script d'entraînement de l'IA (`train_model.py`) s'attend à lire ce fichier. Créez un fichier nommé `db.config` :

```ini
[postgresql]
dbname = soc_db
user = postgres
password = votre_mot_de_passe_sql
host = localhost
port = 5432

```
## **Étape 3 : Configuration de Wazuh (SIEM)**

1. **Ajouter les règles de détection :**
Copiez le contenu du fichier `soc_rules.xml` fourni dans le projet et collez-le dans le fichier des règles locales de votre serveur Wazuh (généralement situé dans `/var/ossec/etc/rules/local_rules.xml`).
2. **Activer la réception Syslog sur Wazuh :**
Ouvrez le fichier de configuration principal de Wazuh (`/var/ossec/etc/ossec.conf`) et ajoutez ce bloc pour autoriser la réception des logs UDP sur le port 514 :
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>IP_DE_VOTRE_MACHINE_BACKEND</allowed-ips>
</remote>

```


3. **Redémarrez Wazuh** : `systemctl restart wazuh-manager`

---

## **Étape 4 : Lancement du Backend (API)**

1. Ouvrez un terminal dans le dossier de votre projet.
2. Installez les dépendances Python :
```bash
pip install -r requirements.txt

```


3. Lancez le serveur FastAPI :
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

```

---

## **Étape 5 : Lancement de l'Agent de collecte**

L'agent va interroger votre machine à intervalles réguliers et envoyer les données au backend. Il nécessite souvent les droits administrateur pour lire toutes les informations système via `osquery`.

Ouvrez un nouveau terminal et lancez :

```bash
sudo python3 osquery_agent.py --api-url http://localhost:8000/api --interval 30

```

---

## **Étape 6 : L'Interface Graphique (Dashboard)**

Pour visualiser les données, ouvrez simplement le fichier `index.html` dans n'importe quel navigateur web moderne.

Le tableau de bord va se connecter automatiquement à `http://localhost:8000` et afficher les alertes de sécurité, les anomalies détectées par l'IA et l'inventaire de vos vulnérabilités logicielles.

---

## **Étape 7 : Entraînement de l'Intelligence Artificielle**

Au premier lancement, le modèle de Machine Learning est "vierge". Pour qu'il puisse détecter des anomalies, il doit d'abord apprendre ce qu'est un comportement **normal**.

1. Laissez tourner votre agent (`osquery_agent.py`) et votre backend (`main.py`) pendant quelques heures (ou idéalement quelques jours) pendant l'utilisation normale de votre machine.
2. Une fois suffisamment de logs normaux collectés dans la base de données, lancez le script d'entraînement :

```bash
python3 train_model.py

```


3. Ce script va filtrer les attaques connues, apprendre le profil réseau/système standard de vos machines, et générer le fichier `ml_behavioral_model.joblib`.
4. **Redémarrez votre backend** (`uvicorn main:app ...`) pour qu'il charge ce nouveau cerveau IA. Le système est désormais pleinement opérationnel.