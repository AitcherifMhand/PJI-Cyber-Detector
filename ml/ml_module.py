import math

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from collections import defaultdict, deque
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
 
 # RULES ENGINE 

class RulesEngine:
    """
    Moteur de règles expertes cybersécurité.
    Retourne : (score 0–100, raisons[], remédiation, axes de risque)
    """

    def evaluate(self, log: dict, wf: dict) -> tuple[float, list[str], str, dict]:
        score   = 0.0
        reasons = []

        # Axes de risque indépendants (pour scoring multi-axe)
        axes = {
            "exfiltration":  0.0,
            "lateral":       0.0,
            "privilege":     0.0,
            "persistence":   0.0,
            "recon":         0.0,
        }

        bytes_sent = int(log.get("bytes_sent", 0) or 0)
        port       = int(log.get("port", 0) or 0)
        proc       = str(log.get("process_name", "") or "").lower().strip()
        msg        = str(log.get("alert_message", "") or "").upper()
        msg_words  = set(msg.split())

        #  Reverse shells / C2
        if port in MALICIOUS_PORTS:
            score += 55
            axes["lateral"] += 55
            reasons.append(f"Port C2/reverse shell connu ({port})")

        if proc in MALICIOUS_PROCESSES:
            score += 65
            axes["lateral"] += 65
            reasons.append(f"Processus malveillant ({proc})")

        #  Exfiltration volume
        if bytes_sent >= EXFIL_BYTES_CRITICAL:
            score += 45
            axes["exfiltration"] += 45
            reasons.append(f"Volume critique exfiltré ({bytes_sent:,} octets)")
        elif bytes_sent >= EXFIL_BYTES_HIGH:
            score += 25
            axes["exfiltration"] += 25
            reasons.append(f"Volume élevé exfiltré ({bytes_sent:,} octets)")

        #  Exfiltration taux (fenêtres temporelles)
        bytes_5m = wf.get("bytes_sent_5m", 0)
        if bytes_5m >= EXFIL_BYTES_CRITICAL * 3:
            score += 35
            axes["exfiltration"] += 35
            reasons.append(f"Débit massif sur 5 min ({bytes_5m:,} octets)")

        #  Burst de requêtes
        rpm = wf.get("req_per_min", 0)
        if rpm >= BURST_REQUESTS_CRIT:
            score += 40
            axes["recon"] += 40
            reasons.append(f"Burst critique ({rpm} req/min) — probable automatisation")
        elif rpm >= BURST_REQUESTS_WARN:
            score += 20
            axes["recon"] += 20
            reasons.append(f"Taux de requêtes élevé ({rpm} req/min)")

        #  Scan de ports (entropie + nb ports distincts)
        unique_ports = wf.get("unique_ports_1h", 0)
        if unique_ports >= PORT_ENTROPY_HIGH:
            score += 30
            axes["recon"] += 30
            reasons.append(f"Scan de ports probable ({unique_ports} ports distincts/heure)")

        #  Outils d'exfiltration (curl, wget, tar, zip…)
        if proc in EXFIL_TOOLS or any(t in msg for t in [t.upper() for t in EXFIL_TOOLS]):
            score += 30
            axes["exfiltration"] += 30
            reasons.append(f"Outil de transfert/compression détecté ({proc})")

        #  SQL dangereux (DROP, DELETE, TRUNCATE)
        if msg_words & SQL_DANGER:
            score += 35
            axes["exfiltration"] += 35
            matched = msg_words & SQL_DANGER
            reasons.append(f"Opération SQL destructrice ({', '.join(matched)})")

        #  SQL exfiltration (SELECT massif, UNION, OUTFILE)
        if msg_words & SQL_EXFIL:
            score += 20
            axes["exfiltration"] += 20
            reasons.append("Requête SQL d'extraction détectée")

        #  Accumulation SQL dangereuse (fenêtre 1h)
        if wf.get("sql_danger_count_1h", 0) >= 3:
            score += 20
            axes["exfiltration"] += 20
            reasons.append(f"Rafale SQL dangereuse ({wf['sql_danger_count_1h']} ops/heure)")

        #  Escalade de privilèges
        if wf.get("sudo_count_1h", 0) >= 5:
            score += 25
            axes["privilege"] += 25
            reasons.append(f"Usage sudo intensif ({wf['sudo_count_1h']}x/heure)")

        #  Bruteforce login
        if wf.get("failed_login_count_1h", 0) >= 10:
            score += 30
            axes["lateral"] += 30
            reasons.append(f"Bruteforce détecté ({wf['failed_login_count_1h']} échecs/heure)")

        #  Activité nocturne (horaire inhabituel)
        hour = _parse_ts(log.get("timestamp")).hour
        if hour >= 22 or hour <= 5:
            if score > 0:   # Amplificateur seulement si déjà suspect
                score += 10
                reasons.append("Activité nocturne (heure anormale)")

        #  Archives suspectes (staging avant exfil)
        if wf.get("archive_count_1h", 0) >= 3:
            score += 20
            axes["exfiltration"] += 20
            reasons.append(f"Création massive d'archives ({wf['archive_count_1h']}x/heure) — staging probable")

        # Normalisation
        score = min(round(score, 2), 100)
        for k in axes:
            axes[k] = min(axes[k], 100)

        remediation = self._remediation(score, axes, proc, port)
        return score, reasons, remediation, axes

    def _remediation(self, score: float, axes: dict, proc: str, port: int) -> str:
        if score < RISK_THRESHOLDS["WARNING"]:
            return "Aucune action requise."

        actions = []
        if axes["exfiltration"] >= 40:
            actions.append("Bloquer IP source / destination")
        if axes["lateral"] >= 40 or port in MALICIOUS_PORTS or proc in MALICIOUS_PROCESSES:
            actions.append("Kill processus immédiat (Active Response Wazuh)")
        if axes["exfiltration"] >= 35:
            actions.append("Isoler l'hôte du réseau")
        if axes["privilege"] >= 25:
            actions.append("Désactiver le compte utilisateur")
        if axes["recon"] >= 30:
            actions.append("Rate-limiting + blacklist IP")
        if not actions:
            actions.append("Surveillance accrue (logging renforcé)")

        return " | ".join(actions)

def compute_risk_score(ml_score: float, rules_score: float, is_ml_anomaly: bool) -> float:
    """
    Score global pondéré :
        40% ML comportemental  (non biaisé, détecte l'inconnu)
        60% Règles expertes    (précision métier SOC)

    Boost si le ML détecte une anomalie pure sans règle associée.
    """
    risk = (ml_score * 0.4) + (rules_score * 0.6)
    if is_ml_anomaly and risk < RISK_THRESHOLDS["WARNING"]:
        risk += 20   # Déviation comportementale sans signature connue
    return min(round(risk, 2), 100)


def classify_severity(risk_score: float) -> tuple[str, bool]:
    if risk_score >= RISK_THRESHOLDS["CRITICAL"]:
        return "CRITICAL", True
    elif risk_score >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH", True
    elif risk_score >= RISK_THRESHOLDS["WARNING"]:
        return "WARNING", True
    return "INFO", False


# DÉTECTEUR PRINCIPAL

class CyberAnomalyDetector:
    """Détecteur d'anomalies cyber basé sur ML"""
    
    def __init__(self, contamination=0.1):
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            n_estimators=300,       
            contamination=contamination,
            max_samples="auto",
            max_features=1.0,
            bootstrap=False,
            random_state=42,
            n_jobs=-1,
        )
        self.is_trained      = False
        self.rules_engine    = RulesEngine()
        self._host_windows: dict[str, HostBehaviorWindow] = defaultdict(HostBehaviorWindow)

    def fit(self, logs_df: pd.DataFrame) -> "CyberAnomalyDetector":
        """
        Apprend le comportement normal sur un dataset historique.
        logs_df : DataFrame avec colonnes Osquery standard.
        """
        print(f"[ML] Extraction des features comportementales ({len(logs_df)} événements)...")
        X = extract_features_batch(logs_df)

        # Vérification colonnes
        missing = set(FEATURE_COLUMNS) - set(X.columns)
        for col in missing:
            X[col] = 0
        X = X[FEATURE_COLUMNS].astype(float)

        print("[ML] Normalisation StandardScaler...")
        X_scaled = self.scaler.fit_transform(X)

        print("[ML] Entraînement Isolation Forest...")
        self.isolation_forest.fit(X_scaled)

        self.is_trained = True
        print(f"[ML] ✓ Modèle comportemental entraîné ({len(FEATURE_COLUMNS)} features, contamination={self.contamination})")
        return self

    # Prédiction temps réel 

    def predict(self, log: dict) -> dict:
        """
        Analyse un événement en temps réel.
        Retourne un dictionnaire de résultat complet.
        """
        hostname = str(log.get("hostname", "unknown"))

        # 1. Mise à jour des fenêtres comportementales
        wf = self._host_windows[hostname].update(log)

        # 2. Extraction des features
        feat = extract_features(log, window_features=wf)
        X = pd.DataFrame([feat], columns=FEATURE_COLUMNS).fillna(0).astype(float)

        # 3. Score ML (Isolation Forest)
        ml_score       = 0.0
        is_ml_anomaly  = False

        if self.is_trained:
            for col in FEATURE_COLUMNS:
                if col not in X.columns:
                    X[col] = 0
            X = X[FEATURE_COLUMNS]
            X_scaled = self.scaler.transform(X)

            raw_score      = self.isolation_forest.decision_function(X_scaled)[0]
            prediction     = self.isolation_forest.predict(X_scaled)[0]
            is_ml_anomaly  = (prediction == -1)

            # Conversion : plus raw_score est négatif, plus c'est anormal
            # On mappe [-0.5, 0.5] → [100, 0]
            ml_score = float(np.clip((0.5 - raw_score) * 100, 0, 100))

        # 4. Corrélation règles SOC
        rules_score, reasons, remediation, risk_axes = self.rules_engine.evaluate(log, wf)

        # 5. Score global
        risk_score = compute_risk_score(ml_score, rules_score, is_ml_anomaly)

        # Ajouter la raison ML si détection comportementale pure
        if is_ml_anomaly and rules_score < RISK_THRESHOLDS["WARNING"]:
            reasons.append("Déviation comportementale pure (Isolation Forest)")

        # 6. Classification
        severity, is_anomaly = classify_severity(risk_score)

        # Remédiation minimale si WARNING sans règle
        if is_anomaly and remediation == "Aucune action requise.":
            remediation = "Surveillance accrue (logging renforcé)"

        return {
            "is_anomaly":    is_anomaly,
            "severity":      severity,
            "risk_score":    risk_score,
            "ml_score":      round(ml_score, 2),
            "rules_score":   round(rules_score, 2),
            "ml_anomaly":    is_ml_anomaly,
            "reasons":       reasons,
            "remediation":   remediation,
            "risk_axes":     risk_axes,       # Décomposition multi-axe pour le dashboard
            "window_state":  wf,              # État comportemental courant de l'hôte
        }

    
    def save_model(self, path: str = "ml_behavioral_model.joblib") -> None:
        joblib.dump({
            "scaler":           self.scaler,
            "isolation_forest": self.isolation_forest,
            "is_trained":       self.is_trained,
            "contamination":    self.contamination,
        }, path)
        print(f"[ML] Modèle sauvegardé → {path}")

    @classmethod
    def load_model(cls, path: str = "ml_behavioral_model.joblib") -> "CyberAnomalyDetector":
        if not os.path.exists(path):
            print(f"[ML] Aucun modèle trouvé à {path} — initialisation vierge.")
            return cls()
        data = joblib.load(path)
        detector = cls(contamination=data["contamination"])
        detector.scaler           = data["scaler"]
        detector.isolation_forest = data["isolation_forest"]
        detector.is_trained       = data["is_trained"]
        print(f"[ML] Modèle chargé depuis {path} (trained={detector.is_trained})")
        return detector
    
    save_model  = save_model
    load_model  = classmethod(lambda cls, path="ml_behavioral_model.joblib": cls.load(path))

def _parse_ts(ts) -> datetime.datetime:
    """Parse timestamp flexible (datetime, str ISO, None)."""
    if isinstance(ts, datetime.datetime):
        return ts
    if isinstance(ts, str):
        try:
            return datetime.datetime.fromisoformat(ts)
        except ValueError:
            pass
    return datetime.datetime.now()


def _entropy(values: list) -> float:
    """Entropie de Shannon sur une liste de valeurs discrètes."""
    if not values:
        return 0.0
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    n = len(values)
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c > 0)
