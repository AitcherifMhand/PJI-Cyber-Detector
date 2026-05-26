import pandas as pd
import psycopg2
import configparser
from ml_module import CyberAnomalyDetector

print("[*] Connexion à la base de données PostgreSQL...")
config = configparser.ConfigParser()
config.read('db.config')

try:
    conn = psycopg2.connect(
        dbname=config['postgresql']['dbname'],
        user=config['postgresql']['user'],
        password=config['postgresql']['password'],
        host=config['postgresql']['host'],
        port=config['postgresql']['port']
    )
    
    query = "SELECT * FROM alerts"
    logs_df = pd.read_sql_query(query, conn)
    conn.close()
    
    if logs_df.empty:
        print("[-] La base de données est vide. Générez d'abord du trafic avec osquery_agent.py.")
    else:
        print(f"[+] {len(logs_df)} événements récupérés. Début de l'entraînement...")
        
        # Initialisation et entraînement du modèle
        detector = CyberAnomalyDetector(contamination=0.1)
        detector.fit(logs_df)
        
        # Sauvegarde du modèle
        detector.save_model('ml_behavioral_model.joblib')
        print("[+] Fichier 'ml_behavioral_model.joblib' généré avec succès !")

except Exception as e:
    print(f"[!] Erreur lors de l'entraînement : {e}")