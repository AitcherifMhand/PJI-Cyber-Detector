import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from collections import defaultdict
import datetime
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
            n_estimators=200
        )
        self.is_trained = False
        # Suivi de l'état comportemental en mémoire (Time Windows)
        self.host_state = defaultdict(lambda: {
            'last_seen': datetime.datetime.now(),
            'requests_last_minute': 0,
            'bytes_sent_last_5m': 0,
            'unique_ports_contacted': set(),
            'suspicious_process_count': 0
        })
        
    def extract_features(self, logs_df):
        """
        Extrait les features purement comportementales et de volume.
        (Pas de NLP, pas d'analyse de texte brut ici)
        """
        features = pd.DataFrame()
        
        # 1. Features Temporelles
        if 'timestamp' in logs_df.columns:
            logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
            features['hour'] = logs_df['timestamp'].dt.hour
            features['is_night'] = (features['hour'].between(22, 5)).astype(int)
        else:
            features['hour'] = datetime.datetime.now().hour
            features['is_night'] = int(22 <= features['hour'].iloc[0] <= 23 or 0 <= features['hour'].iloc[0] <= 5)

        # 2. Features de Volume et Réseau
        features['bytes_sent'] = logs_df.get('bytes_sent', 0).fillna(0)
        features['bytes_log'] = np.log1p(features['bytes_sent'])
        features['is_unusual_port'] = (logs_df.get('port', 0).fillna(0) > 1024).astype(int)
        
        # 3. Features d'état (uniquement en prédiction temps réel)
        if not is_training and len(logs_df) == 1:
            state_feats = self._update_and_get_state_features(logs_df.iloc[0].to_dict())
            features['req_per_min'] = state_feats['requests_per_minute']
            features['bytes_5m'] = state_feats['bytes_sent_5m']
            features['ports_entropy'] = state_feats['unique_ports_count']
        else:
            features['req_per_min'] = 1
            features['bytes_5m'] = features['bytes_sent']
            features['ports_entropy'] = 1

        return features
    def _update_and_get_state_features(self, log_dict):
        """Met à jour l'état de l'hôte et retourne les features temporelles"""
        host = log_dict.get('hostname', 'unknown')
        state = self.host_state[host]
        now = pd.to_datetime(log_dict.get('timestamp', datetime.datetime.now()))
        
        time_diff = (now - state['last_seen']).total_seconds()
        
        # Réinitialisation des fenêtres glissantes si trop de temps s'est écoulé
        if time_diff > 60:
            state['requests_last_minute'] = 0
        if time_diff > 300:
            state['bytes_sent_last_5m'] = 0
            
        # Mise à jour
        state['requests_last_minute'] += 1
        state['bytes_sent_last_5m'] += log_dict.get('bytes_sent', 0)
        state['unique_ports_contacted'].add(log_dict.get('port', 0))
        state['last_seen'] = now
        
        return {
            'requests_per_minute': state['requests_last_minute'],
            'bytes_sent_5m': state['bytes_sent_last_5m'],
            'unique_ports_count': len(state['unique_ports_contacted'])
        }
    
    def evaluate_rules(self, log_dict):
        """Moteur de règles cyber (Corrélation)"""
        rules_score = 0
        reasons = []
        remediation = "Aucune action requise."
        
        msg = str(log_dict.get('alert_message', '')).upper()
        process = str(log_dict.get('process_name', '')).lower()
        port = log_dict.get('port', 0)
        bytes_sent = log_dict.get('bytes_sent', 0)

        # Exfiltration / Volume
        if bytes_sent > 50000:
            rules_score += 40
            reasons.append("Volume d'exfiltration massif")
            remediation = "Bloquer IP et isoler l'hôte"
            
        if any(kw in msg for kw in ['CURL', 'WGET', 'TAR', 'ZIP']):
            rules_score += 30
            reasons.append("Outil de transfert/compression détecté")
            
        # Activité process/port suspecte (Reverse Shells, C2)
        if port in [4444, 1337, 8080]:
            rules_score += 50
            reasons.append(f"Port sensible ({port}) utilisé")
            remediation = "Kill Processus immédiat"
            
        if process in ['nc', 'ncat', 'netcat', 'msfconsole', 'meterpreter']:
            rules_score += 60
            reasons.append(f"Processus malveillant connu ({process})")
            remediation = "Kill Processus immédiat"

        # SQL Injection / Dump
        if any(kw in msg for kw in ['SELECT', 'DROP', 'DELETE']):
            rules_score += 30
            reasons.append("Activité SQL suspecte")
            if "DROP" in msg:
                remediation = "Révoquer accès BDD"

        return min(rules_score, 100), reasons, remediation
    
    def fit(self, logs_df):
            """Apprend le comportement normal (uniquement IF)"""
            print("[ML] Extraction des features comportementales...")
            X = self.extract_features(logs_df, is_training=True)
            
            X_scaled = self.scaler.fit_transform(X)
            
            print(f"[ML] Apprentissage du comportement normal (Isolation Forest sur {X_scaled.shape[0]} événements)...")
            self.isolation_forest.fit(X_scaled)
            
            self.is_trained = True
            print("[ML] Modèle comportemental entraîné avec succès!")
            return self
    def predict(self, log_entry_dict):
        """Analyse un événement, score le risque et propose une remédiation"""
        log_df = pd.DataFrame([log_entry_dict])
        
        # 1. Extraction Features & Prédiction ML (Score de -1 à 1, on normalise de 0 à 100)
        ml_score = 0
        is_ml_anomaly = False
        
        if self.is_trained:
            X = self.extract_features(log_df, is_training=False)
            # Assurer la consistance des colonnes
            for col in self.scaler.feature_names_in_:
                if col not in X.columns:
                    X[col] = 0
            X = X[self.scaler.feature_names_in_]
            
            X_scaled = self.scaler.transform(X)
            
            # Plus la distance est négative, plus c'est anormal. On l'inverse pour le score.
            raw_ml_score = self.isolation_forest.decision_function(X_scaled)[0]
            prediction = self.isolation_forest.predict(X_scaled)[0]
            
            is_ml_anomaly = (prediction == -1)
            # Conversion en "Indice de confiance d'anomalie" (0 à 100)
            ml_score = np.clip((0.5 - raw_ml_score) * 100, 0, 100)
        
        # 2. Corrélation avec les Règles SOC
        rules_score, reasons, recommended_remediation = self.evaluate_rules(log_entry_dict)
        
        # 3. Scoring de Risque Global
        # Le ML compte pour 40%, les règles expertes pour 60%
        risk_score = (ml_score * 0.4) + (rules_score * 0.6)
        risk_score = min(round(risk_score, 2), 100)
        
        # Si le ML détecte une anomalie pure, on booste le score
        if is_ml_anomaly and risk_score < 30:
            risk_score += 20
            reasons.append("Déviation comportementale (ML)")

        # 4. Classification de Sévérité
        severity = "INFO"
        is_anomaly = False
        
        if risk_score >= 80:
            severity = "CRITICAL"
            is_anomaly = True
        elif risk_score >= 60:
            severity = "HIGH"
            is_anomaly = True
        elif risk_score >= 30:
            severity = "WARNING"
            is_anomaly = True
            if recommended_remediation == "Aucune action requise.":
                recommended_remediation = "Surveillance accrue"

        return {
            'is_anomaly': is_anomaly,
            'severity': severity,
            'risk_score': risk_score,
            'ml_anomaly': bool(is_ml_anomaly),
            'reasons': reasons,
            'remediation': recommended_remediation
        }
    
    def save_model(self, path='ml_behavioral_model.joblib'):
        model_data = {
            'scaler': self.scaler,
            'isolation_forest': self.isolation_forest,
            'is_trained': self.is_trained,
            'contamination': self.contamination
        }
        joblib.dump(model_data, path)

    @classmethod
    def load_model(cls, path='ml_behavioral_model.joblib'):
        if not os.path.exists(path):
            return cls()
        model_data = joblib.load(path)
        detector = cls(contamination=model_data['contamination'])
        detector.scaler = model_data['scaler']
        detector.isolation_forest = model_data['isolation_forest']
        detector.is_trained = model_data['is_trained']
        return detector