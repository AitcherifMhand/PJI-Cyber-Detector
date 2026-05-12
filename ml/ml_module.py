import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

class CyberAnomalyDetector:
    """Détecteur d'anomalies cyber basé sur ML"""
    
    def __init__(self, contamination=0.1):
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100
        )
        self.rf_classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=42
        )
        self.tfidf_vectorizer = TfidfVectorizer(max_features=100)
        self.label_encoder = LabelEncoder()
        self.port_encoder = LabelEncoder()
        self.is_trained = False
        self.feature_importance = {}
        
        # Statistiques de base par hôte
        self.host_stats = defaultdict(lambda: {
            'login_count': 0,
            'avg_bytes_sent': 0,
            'common_ports': set(),
            'common_processes': set(),
            'hourly_activity': defaultdict(int)
        })
        
    def extract_features(self, logs_df):
        """
        Extrait les features avancées à partir des logs bruts
        
        Features extraites:
        - Horaires (heure, jour de semaine)
        - Longueur du message
        - Présence de mots-clés suspects dans le message
        - Encodage du port
        - Encodage du processus
        - Bytes envoyés (normalisés)
        - Fréquence d'activité par hôte
        - Score TF-IDF du message d'alerte
        """
        features = pd.DataFrame()
        
        # Features temporelles
        if 'timestamp' in logs_df.columns:
            logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
            features['hour'] = logs_df['timestamp'].dt.hour
            features['day_of_week'] = logs_df['timestamp'].dt.dayofweek
            features['is_business_hours'] = (features['hour'].between(8, 18)).astype(int)
            features['is_night'] = (features['hour'].between(22, 5)).astype(int)
        
        # Features textuelles du message
        if 'alert_message' in logs_df.columns:
            features['msg_length'] = logs_df['alert_message'].str.len()
            features['has_select'] = logs_df['alert_message'].str.contains('SELECT', case=False).astype(int)
            features['has_drop'] = logs_df['alert_message'].str.contains('DROP', case=False).astype(int)
            features['has_delete'] = logs_df['alert_message'].str.contains('DELETE', case=False).astype(int)
            features['has_curl'] = logs_df['alert_message'].str.contains('curl|wget', case=False, regex=True).astype(int)
            features['has_suspicious'] = logs_df['alert_message'].str.contains(
                'nc|netcat|reverse|shell|backdoor|exploit', case=False, regex=True
            ).astype(int)
            
            # TF-IDF des messages
            tfidf_matrix = self.tfidf_vectorizer.fit_transform(logs_df['alert_message'].fillna(''))
            tfidf_df = pd.DataFrame(
                tfidf_matrix.toarray(),
                columns=[f'tfidf_{i}' for i in range(tfidf_matrix.shape[1])]
            )
            features = pd.concat([features, tfidf_df], axis=1)
        
        # Features de ports
        if 'port' in logs_df.columns:
            features['port'] = logs_df['port'].fillna(0)
            features['is_sensitive_port'] = logs_df['port'].isin([22, 3306, 4444, 1337, 8080]).astype(int)
            features['is_unusual_port'] = (logs_df['port'] > 1024).astype(int)
        
        # Features de processus
        if 'process_name' in logs_df.columns:
            features['process_is_system'] = logs_df['process_name'].str.lower().isin(
                ['systemd', 'kernel', 'init']
            ).astype(int)
            features['process_is_suspicious'] = logs_df['process_name'].str.lower().isin(
                ['nc', 'ncat', 'netcat', 'msfconsole', 'meterpreter']
            ).astype(int)
            features['process_length'] = logs_df['process_name'].str.len()
        
        # Features réseau
        if 'bytes_sent' in logs_df.columns:
            features['bytes_sent'] = logs_df['bytes_sent'].fillna(0)
            features['bytes_sent_log'] = np.log1p(features['bytes_sent'])
            features['is_large_transfer'] = (features['bytes_sent'] > 50000).astype(int)
        
        # Features d'hôte
        if 'hostname' in logs_df.columns:
            host_counts = logs_df['hostname'].value_counts()
            features['host_activity_freq'] = logs_df['hostname'].map(host_counts)
            features['host_activity_rank'] = logs_df['hostname'].map(
                {host: i for i, host in enumerate(host_counts.index)}
            )
        
        # Remplir les NaN
        features = features.fillna(0)
        
        return features
    
    def fit(self, logs_df):
        """Entraîne le modèle sur les données historiques"""
        print("[ML] Extraction des features...")
        X = self.extract_features(logs_df)
        
        # Normaliser les features numériques
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X_scaled = self.scaler.fit_transform(X[numeric_cols])
        X_scaled = pd.DataFrame(X_scaled, columns=numeric_cols)
        
        print(f"[ML] Features extraites: {X_scaled.shape[1]} dimensions")
        print(f"[ML] Échantillons d'entraînement: {X_scaled.shape[0]}")
        
        # Entraîner Isolation Forest (non supervisé)
        print("[ML] Entraînement Isolation Forest...")
        self.isolation_forest.fit(X_scaled)
        
        # Créer des pseudo-labels basés sur les règles et l'IF pour l'entraînement supervisé
        if_scores = self.isolation_forest.decision_function(X_scaled)
        if_predictions = self.isolation_forest.predict(X_scaled)
        
        # Combiner avec des règles expertes
        rule_based_anomalies = (
            (X['has_suspicious'] == 1) | 
            (X['is_sensitive_port'] == 1) | 
            (X['is_large_transfer'] == 1) |
            (X['is_night'] == 1) & (X['is_unusual_port'] == 1)
        ).astype(int)
        
        # Label final : IF + règles expertes
        y = ((if_predictions == -1) | (rule_based_anomalies == 1)).astype(int)
        
        print(f"[ML] Distribution des anomalies: {y.sum()} anomalies sur {len(y)} échantillons ({y.mean()*100:.1f}%)")
        
        # Entraîner le Random Forest supervisé
        print("[ML] Entraînement Random Forest...")
        self.rf_classifier.fit(X_scaled, y)
        
        # Calculer l'importance des features
        self.feature_importance = dict(zip(
            numeric_cols,
            self.rf_classifier.feature_importances_
        ))
        
        # Trier par importance
        self.feature_importance = dict(sorted(
            self.feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10])
        
        print("[ML] Top 10 features importantes:")
        for feat, imp in list(self.feature_importance.items())[:10]:
            print(f"  - {feat}: {imp:.4f}")
        
        self.is_trained = True
        print("[ML] Modèle entraîné avec succès!")
        
        return self
    
    def predict(self, log_entry_dict):
        """Prédit si une nouvelle entrée de log est une anomalie"""
        if not self.is_trained:
            # Fallback sur les règles si le modèle n'est pas entraîné
            return self._rule_based_prediction(log_entry_dict)
        
        # Convertir en DataFrame
        log_df = pd.DataFrame([log_entry_dict])
        if 'timestamp' not in log_df.columns:
            log_df['timestamp'] = pd.Timestamp.now()
        
        # Extraire les features
        X = self.extract_features(log_df)
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        
        # S'assurer que toutes les colonnes attendues sont présentes
        expected_cols = self.scaler.feature_names_in_ if hasattr(self.scaler, 'feature_names_in_') else numeric_cols
        for col in expected_cols:
            if col not in X.columns:
                X[col] = 0
        X = X[expected_cols]
        
        # Normaliser
        X_scaled = self.scaler.transform(X)
        
        # Prédiction RF
        rf_pred = self.rf_classifier.predict(X_scaled)[0]
        rf_proba = self.rf_classifier.predict_proba(X_scaled)[0]
        
        # Score d'anomalie IF
        if_score = self.isolation_forest.decision_function(X_scaled)[0]
        
        # Score combiné (0 à 1, plus élevé = plus anormal)
        anomaly_score = 1 - (if_score - self.isolation_forest.offset_) / (
            np.abs(self.isolation_forest.offset_) * 2
        )
        anomaly_score = np.clip(anomaly_score, 0, 1)
        
        is_anomaly = rf_pred == 1 or anomaly_score > 0.7
        
        return {
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': float(anomaly_score),
            'rf_prediction': int(rf_pred),
            'confidence': float(max(rf_proba)),
            'top_features': self.feature_importance
        }
    
    def predict_batch(self, logs_list):
        """Prédit sur un lot de logs"""
        results = []
        for log in logs_list:
            results.append(self.predict(log))
        return results
    
    def _rule_based_prediction(self, log_entry):
        """Fallback basé sur des règles expertes"""
        is_anomaly = False
        reasons = []
        
        # Règles par port
        if log_entry.get('port') in [4444, 1337]:
            is_anomaly = True
            reasons.append("Port suspect")
        
        # Règles par processus
        if str(log_entry.get('process_name', '')).lower() in ['nc', 'ncat', 'netcat', 'msfconsole']:
            is_anomaly = True
            reasons.append("Processus suspect")
        
        # Règles par message
        msg = str(log_entry.get('alert_message', '')).upper()
        if any(kw in msg for kw in ['SELECT', 'DROP', 'DELETE', 'INSERT']):
            is_anomaly = True
            reasons.append("Commande SQL suspecte")
        
        if any(kw in msg for kw in ['CURL', 'WGET']):
            is_anomaly = True
            reasons.append("Exfiltration potentielle")
        
        # Règles par volume
        if log_entry.get('bytes_sent', 0) > 50000:
            is_anomaly = True
            reasons.append("Transfert volumineux")
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': 0.8 if is_anomaly else 0.2,
            'rf_prediction': int(is_anomaly),
            'confidence': 0.9 if is_anomaly else 0.7,
            'reasons': reasons
        }
    
    def get_model_health(self):
        """Retourne l'état du modèle"""
        return {
            'is_trained': self.is_trained,
            'contamination': self.contamination,
            'feature_importance': self.feature_importance,
            'n_features': len(self.feature_importance)
        }
    
    def save_model(self, path='ml_model.joblib'):
        """Sauvegarde le modèle"""
        model_data = {
            'scaler': self.scaler,
            'isolation_forest': self.isolation_forest,
            'rf_classifier': self.rf_classifier,
            'tfidf_vectorizer': self.tfidf_vectorizer,
            'is_trained': self.is_trained,
            'feature_importance': self.feature_importance,
            'contamination': self.contamination
        }
        joblib.dump(model_data, path)
        print(f"[ML] Modèle sauvegardé dans {path}")
    
    @classmethod
    def load_model(cls, path='ml_model.joblib'):
        """Charge un modèle sauvegardé"""
        if not os.path.exists(path):
            print(f"[ML] Pas de modèle trouvé à {path}, création d'un nouveau")
            return cls()
        
        model_data = joblib.load(path)
        detector = cls(contamination=model_data['contamination'])
        detector.scaler = model_data['scaler']
        detector.isolation_forest = model_data['isolation_forest']
        detector.rf_classifier = model_data['rf_classifier']
        detector.tfidf_vectorizer = model_data['tfidf_vectorizer']
        detector.is_trained = model_data['is_trained']
        detector.feature_importance = model_data['feature_importance']
        print(f"[ML] Modèle chargé depuis {path}")
        return detector


class AdaptiveThresholdDetector:
    """
    Détecteur adaptatif qui apprend les patterns normaux par hôte
    et s'adapte au fil du temps
    """
    
    def __init__(self, window_size=100):
        self.window_size = window_size
        self.host_profiles = defaultdict(lambda: {
            'port_freq': defaultdict(int),
            'process_freq': defaultdict(int),
            'hourly_activity': defaultdict(int),
            'avg_bytes_sent': 0,
            'bytes_std': 0,
            'total_logs': 0,
            'recent_scores': []
        })
        
    def update_profile(self, log_entry):
        """Met à jour le profil d'un hôte"""
        host = log_entry.get('hostname', 'unknown')
        profile = self.host_profiles[host]
        
        profile['total_logs'] += 1
        profile['port_freq'][log_entry.get('port', 0)] += 1
        profile['process_freq'][log_entry.get('process_name', '')] += 1
        
        if 'timestamp' in log_entry:
            hour = pd.to_datetime(log_entry['timestamp']).hour
            profile['hourly_activity'][hour] += 1
        
        if 'bytes_sent' in log_entry and log_entry['bytes_sent'] > 0:
            n = profile['total_logs']
            old_avg = profile['avg_bytes_sent']
            profile['avg_bytes_sent'] = old_avg + (log_entry['bytes_sent'] - old_avg) / n
        
    def is_anomalous_for_host(self, log_entry, threshold=2.0):
        """Vérifie si un log est anormal pour son hôte"""
        host = log_entry.get('hostname', 'unknown')
        profile = self.host_profiles[host]
        
        if profile['total_logs'] < 10: 
            return False
        
        anomaly_score = 0
        reasons = []
        
        # Port inhabituel
        port = log_entry.get('port', 0)
        if port > 0:
            port_freq = profile['port_freq'].get(port, 0)
            if port_freq == 0:
                anomaly_score += 0.4
                reasons.append(f"Port {port} jamais vu pour {host}")
            elif port_freq < profile['total_logs'] * 0.01:  # <1% des cas
                anomaly_score += 0.2
                reasons.append(f"Port {port} rare pour {host}")
        
        # Volume inhabituel
        if log_entry.get('bytes_sent', 0) > profile['avg_bytes_sent'] * 3:
            anomaly_score += 0.3
            reasons.append(f"Volume anormal pour {host}")
        
        # Activité horaire inhabituelle
        if 'timestamp' in log_entry:
            hour = pd.to_datetime(log_entry['timestamp']).hour
            hour_freq = profile['hourly_activity'].get(hour, 0)
            if hour_freq == 0 and profile['total_logs'] > 20:
                anomaly_score += 0.3
                reasons.append(f"Activité à une heure inhabituelle pour {host}")
        
        return anomaly_score > 0.5, anomaly_score, reasons


def prepare_training_data(alerts_from_db):
    """
    Prépare les données d'entraînement à partir des alertes en base
    
    Args:
        alerts_from_db: Liste de dictionnaires d'alertes
        
    Returns:
        DataFrame pandas
    """
    if not alerts_from_db:
        return pd.DataFrame()
    
    df = pd.DataFrame(alerts_from_db)
    
    # Ajouter des colonnes si manquantes
    for col in ['timestamp', 'hostname', 'process_name', 'pid', 'port', 
                'alert_message', 'bytes_sent', 'query_text']:
        if col not in df.columns:
            df[col] = ''
    
    return df