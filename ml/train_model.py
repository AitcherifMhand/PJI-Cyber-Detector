import pandas as pd
import psycopg2
import configparser
from ml_module import CyberAnomalyDetector, MALICIOUS_PORTS, MALICIOUS_PROCESSES

print("[*] Connexion à la base de données PostgreSQL...")
config = configparser.ConfigParser()
config.read('db.config')

try:
    conn = psycopg2.connect(**config['postgresql'])
    query = "SELECT * FROM raw_logs"
    logs_df = pd.read_sql_query(query, conn)
    conn.close()
    
    if logs_df.empty:
        print("[-] Base de données vide. Le modèle ne peut pas s'entraîner sans historique de logs normaux.")
    else:
        print(f"[*] Total logs bruts : {len(logs_df)}")
        
        clean_df = logs_df[
            (~logs_df['port'].isin(MALICIOUS_PORTS)) & 
            (~logs_df['process_name'].str.lower().isin(MALICIOUS_PROCESSES))
        ]
        
        print(f"[*] Après filtrage des attaques connues : {len(clean_df)} logs normaux restants.")
        
        # Initialisation et entraînement
        detector = CyberAnomalyDetector(contamination=0.05) 
        detector.fit(clean_df)
        
        detector.save_model('ml_behavioral_model.joblib')

except Exception as e:
    print(f"[!] Erreur lors de l'entraînement : {e}")