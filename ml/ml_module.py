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
 
# CONSTANTES 
RISK_THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH":     60,
    "WARNING":  30,
    "INFO":     0,
}
 
# Ports connus comme dangereux (C2, reverse shells)
MALICIOUS_PORTS = {4444, 1337, 31337, 9001, 6666, 12345}
# Ports à surveiller mais légitimes
SENSITIVE_PORTS = {22, 3306, 5432, 6379, 27017, 8080, 8443}
 
MALICIOUS_PROCESSES = {"nc", "ncat", "netcat", "msfconsole", "meterpreter", "empire", "cobalt"}
EXFIL_TOOLS        = {"curl", "wget", "scp", "rsync", "ftp", "tar", "zip", "7z", "rar"}
SUSPICIOUS_LANGS   = {"python3", "ruby", "perl", "bash", "sh", "powershell"}
 
SQL_DANGER = {"DROP", "DELETE", "TRUNCATE", "ALTER", "GRANT"}
SQL_EXFIL  = {"SELECT", "UNION", "INSERT", "EXPORT", "OUTFILE"}
 
# Seuils de volume
EXFIL_BYTES_CRITICAL = 100_000   # 100 KB → suspect
EXFIL_BYTES_HIGH     = 50_000    # 50 KB → à surveiller
BURST_REQUESTS_WARN  = 60        # >60 req/min → anormal
BURST_REQUESTS_CRIT  = 200       # >200 req/min → attaque probable
PORT_ENTROPY_HIGH    = 10        # >10 ports distincts contactés → scan
 
 
# FENÊTRES TEMPORELLES — État comportemental par hôte
 
class HostBehaviorWindow:
    """
    Maintient l'état comportemental glissant par hôte.
    Windows : 1 min, 5 min, 1 heure.
    Tout en mémoire, pas de DB.
    """
 
    def __init__(self):
        # ring buffer de timestamps pour calculer les taux
        self._events_1m  = deque()   # timestamps sur 1 min
        self._events_5m  = deque()   # timestamps sur 5 min
        self._events_1h  = deque()   # timestamps sur 1 heure
 
        # Compteurs de volume glissants
        self._bytes_1m   = deque()   # (ts, bytes)
        self._bytes_5m   = deque()   # (ts, bytes)
 
        # Ports et IPs uniques (toujours croissants — reset toutes les heures)
        self._ports_1h   = set()
        self._ips_1h     = set()
        self._last_hour_reset = datetime.datetime.now()
 
        # Compteurs de comportements suspects cumulés (reset à l'heure)
        self.sudo_count         = 0
        self.failed_login_count = 0
        self.archive_count      = 0
        self.sql_danger_count   = 0
 
        self.last_seen = datetime.datetime.now()
 
    def _flush_old(self, now: datetime.datetime):
        """Retire les événements hors de leur fenêtre."""
        cutoff_1m = now - datetime.timedelta(minutes=1)
        cutoff_5m = now - datetime.timedelta(minutes=5)
        cutoff_1h = now - datetime.timedelta(hours=1)
 
        while self._events_1m  and self._events_1m[0]  < cutoff_1m:  self._events_1m.popleft()
        while self._events_5m  and self._events_5m[0]  < cutoff_5m:  self._events_5m.popleft()
        while self._events_1h  and self._events_1h[0]  < cutoff_1h:  self._events_1h.popleft()
        while self._bytes_1m   and self._bytes_1m[0][0] < cutoff_1m: self._bytes_1m.popleft()
        while self._bytes_5m   and self._bytes_5m[0][0] < cutoff_5m: self._bytes_5m.popleft()
 
        # Reset ports/IPs/compteurs chaque heure
        if (now - self._last_hour_reset).total_seconds() > 3600:
            self._ports_1h.clear()
            self._ips_1h.clear()
            self.sudo_count         = 0
            self.failed_login_count = 0
            self.archive_count      = 0
            self.sql_danger_count   = 0
            self._last_hour_reset   = now
 
    def update(self, log: dict) -> dict:
        """Met à jour les fenêtres et retourne les features calculées."""
        now = _parse_ts(log.get("timestamp"))
        self._flush_old(now)
 
        bytes_sent = int(log.get("bytes_sent", 0) or 0)
        port       = int(log.get("port", 0) or 0)
        remote_ip  = str(log.get("remote_ip", "") or "")
        process    = str(log.get("process_name", "") or "").lower()
        msg        = str(log.get("alert_message", "") or "").upper()
 
        self._events_1m.append(now)
        self._events_5m.append(now)
        self._events_1h.append(now)
        self._bytes_1m.append((now, bytes_sent))
        self._bytes_5m.append((now, bytes_sent))
 
        if port:       self._ports_1h.add(port)
        if remote_ip:  self._ips_1h.add(remote_ip)
 
        # Compteurs comportementaux
        if "SUDO" in msg or process == "sudo":
            self.sudo_count += 1
        if "FAILED" in msg and "LOGIN" in msg:
            self.failed_login_count += 1
        if any(t in process for t in ("tar", "zip", "7z", "rar", "gzip")):
            self.archive_count += 1
        if any(k in msg for k in SQL_DANGER):
            self.sql_danger_count += 1
 
        self.last_seen = now
 
        # Calcul des features
        req_per_min   = len(self._events_1m)
        req_per_5m    = len(self._events_5m)
        req_per_hour  = len(self._events_1h)
        bytes_1m      = sum(b for _, b in self._bytes_1m)
        bytes_5m      = sum(b for _, b in self._bytes_5m)
        unique_ports  = len(self._ports_1h)
        unique_ips    = len(self._ips_1h)
 
        # Entropie de ports (mesure de dispersion)
        port_entropy = _entropy(list(self._ports_1h)) if self._ports_1h else 0.0
 
        return {
            "req_per_min":           req_per_min,
            "req_per_5m":            req_per_5m,
            "req_per_hour":          req_per_hour,
            "bytes_sent_1m":         bytes_1m,
            "bytes_sent_5m":         bytes_5m,
            "unique_ports_1h":       unique_ports,
            "unique_ips_1h":         unique_ips,
            "port_entropy":          port_entropy,
            "sudo_count_1h":         self.sudo_count,
            "failed_login_count_1h": self.failed_login_count,
            "archive_count_1h":      self.archive_count,
            "sql_danger_count_1h":   self.sql_danger_count,
        }
 
 
 
FEATURE_COLUMNS = [
    # Volume
    "bytes_sent_log",
    "bytes_recv_log",
    "upload_ratio",
    # Temps
    "hour",
    "is_night",
    "is_weekend",
    # Réseau
    "is_malicious_port",
    "is_sensitive_port",
    "unique_ports_1h",
    "unique_ips_1h",
    "port_entropy",
    # Comportement processus
    "is_malicious_process",
    "is_exfil_tool",
    "is_suspicious_lang",
    "archive_count_1h",
    # Requêtes
    "req_per_min",
    "req_per_5m",
    "req_per_hour",
    "bytes_sent_1m",
    "bytes_sent_5m",
    # Activité utilisateur
    "sudo_count_1h",
    "failed_login_count_1h",
    # SQL
    "sql_danger_count_1h",
    "has_sql_exfil",
    "has_sql_danger",
]
 
 
def extract_features(log: dict, window_features: dict | None = None) -> dict:
    """
    Transforme un log brut en vecteur de features numériques.
    window_features : dict retourné par HostBehaviorWindow.update()
    Si window_features=None (training batch), on utilise les valeurs du log directement.
    """
    now    = _parse_ts(log.get("timestamp"))
    bytes_sent = float(log.get("bytes_sent", 0) or 0)
    bytes_recv = float(log.get("bytes_received", 0) or 0)
    port   = int(log.get("port", 0) or 0)
    proc   = str(log.get("process_name", "") or "").lower().strip()
    msg    = str(log.get("alert_message", "") or "").upper()
 
    total_bytes = bytes_sent + bytes_recv + 1e-9
    upload_ratio = bytes_sent / total_bytes
 
    msg_words = set(msg.split())
    has_sql_exfil  = int(bool(msg_words & SQL_EXFIL))
    has_sql_danger = int(bool(msg_words & SQL_DANGER))
 
    wf = window_features or {}
 
    features = {
        # Volume
        "bytes_sent_log":    math.log1p(bytes_sent),
        "bytes_recv_log":    math.log1p(bytes_recv),
        "upload_ratio":      upload_ratio,
        # Temps
        "hour":              now.hour,
        "is_night":          int(now.hour >= 22 or now.hour <= 5),
        "is_weekend":        int(now.weekday() >= 5),
        # Réseau
        "is_malicious_port": int(port in MALICIOUS_PORTS),
        "is_sensitive_port": int(port in SENSITIVE_PORTS),
        "unique_ports_1h":   wf.get("unique_ports_1h", 0),
        "unique_ips_1h":     wf.get("unique_ips_1h", 0),
        "port_entropy":      wf.get("port_entropy", 0.0),
        # Processus
        "is_malicious_process": int(proc in MALICIOUS_PROCESSES),
        "is_exfil_tool":        int(proc in EXFIL_TOOLS),
        "is_suspicious_lang":   int(proc in SUSPICIOUS_LANGS),
        "archive_count_1h":     wf.get("archive_count_1h", 0),
        # Taux de requêtes
        "req_per_min":   wf.get("req_per_min", 1),
        "req_per_5m":    wf.get("req_per_5m", 1),
        "req_per_hour":  wf.get("req_per_hour", 1),
        "bytes_sent_1m": math.log1p(wf.get("bytes_sent_1m", bytes_sent)),
        "bytes_sent_5m": math.log1p(wf.get("bytes_sent_5m", bytes_sent)),
        # Utilisateur
        "sudo_count_1h":         wf.get("sudo_count_1h", 0),
        "failed_login_count_1h": wf.get("failed_login_count_1h", 0),
        # SQL
        "sql_danger_count_1h": wf.get("sql_danger_count_1h", 0),
        "has_sql_exfil":       has_sql_exfil,
        "has_sql_danger":      has_sql_danger,
    }
 
    return features
 
 
def extract_features_batch(logs_df: pd.DataFrame) -> pd.DataFrame:
    """
    Extraction batch pour l'entraînement.
    Pas de fenêtres temporelles (on les simule depuis les données).
    """
    rows = []
    for _, row in logs_df.iterrows():
        f = extract_features(row.to_dict(), window_features=None)
        rows.append(f)
    df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
    return df.fillna(0)
 
 

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