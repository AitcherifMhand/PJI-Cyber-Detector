const API_BASE = "http://localhost:8000";
let allAlerts = [];
let currentFilter = "Tous";
let charts = {};

async function refreshDashboard() {
  await Promise.all([fetchAlerts(), fetchStats()]);
  renderAll();
}

async function fetchAlerts() {
  try {
    const resp = await fetch(`${API_BASE}/api/alerts/?limit=500`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    allAlerts = await resp.json();
    document.getElementById("status-dot").className = "status-dot green";
    document.getElementById("status-text").textContent = "Connecté";
  } catch (e) {
    document.getElementById("status-dot").className = "status-dot red";
    document.getElementById("status-text").textContent = "Déconnecté";
  }
}

async function fetchStats() {
  try {
    const resp = await fetch(`${API_BASE}/api/stats/`);
    if (resp.ok) {
      const stats = await resp.json();
      document.getElementById("m-total").textContent = stats.total_alerts;
      document.getElementById("m-anomalies").textContent = stats.anomalies;
      document.getElementById("m-hosts").textContent = stats.unique_hosts;
    }
  } catch (e) {
    /* ignore */
  }
}

function setFilter(filter, btn) {
  currentFilter = filter;
  document
    .querySelectorAll(".filter-btn")
    .forEach((b) => b.classList.remove("active"));
  btn.classList.add("active");
  renderAlertsTable();
}

function renderAlertsTable() {
  const tbody = document.getElementById("alerts-body");

  let data = allAlerts.filter(
    (a) => !a.resolved && a.process_name !== "Vulnerability-Scanner",
  );

  if (currentFilter === "anomalie") data = data.filter((a) => a.is_anomaly);
  else if (currentFilter === "port")
    data = data.filter(
      (a) => a.port === 4444 || a.port === 1337 || a.port === 22,
    );

  if (!data.length) {
    tbody.innerHTML =
      '<div class="empty-state">Aucune alerte de sécurité active à afficher.</div>';
    return;
  }

  const rows = data
    .slice(0, 30)
    .map((a) => {
      const risk = a.risk_score !== undefined ? a.risk_score : 0;
      const mlScore = a.ml_score !== undefined ? a.ml_score : 0;
      const rulesScore = a.rules_score !== undefined ? a.rules_score : 0;

      const riskColor =
        risk >= 60
          ? "var(--red)"
          : risk >= 30
            ? "var(--amber)"
            : "var(--green)";
      const mlDetails = a.reasons
        ? `<div style="font-size: 11px; color: var(--amber); margin-top: 6px; font-weight: 500;">🤖 IA : ${a.reasons}</div>`
        : "";

      return `
        <tr id="row-${a.id || a.pid}">
            <td style="white-space: nowrap;">${new Date(a.timestamp).toLocaleString("fr-FR")}</td>
            <td><strong>${a.hostname}</strong></td>
            <td>
                ${a.process_name}
                <div style="font-size:10px; color:var(--text-secondary); margin-top:2px;">PID: ${a.pid}</div>
            </td>
            <td><span class="badge badge-port">:${a.port}</span></td>
            <td>
                <div style="max-width:280px; word-wrap:break-word;" title="${a.alert_message}">
                    ${a.alert_message}
                </div>
                ${mlDetails}
            </td>
            <td style="text-align: center;">
                <div style="font-weight: 800; font-size: 14px; color: ${riskColor};">${risk}/100</div>
                <div style="font-size: 9px; color: var(--text-secondary); margin-top:2px; text-transform: uppercase;">
                    ML: ${mlScore} | RÈGLES: ${rulesScore}
                </div>
            </td>
            <td>
                <span id="badge-${a.id || a.pid}" class="badge ${a.is_anomaly ? "badge-anomaly" : "badge-normal"}">
                    ${a.is_anomaly ? "Anomalie" : "Normal"}
                </span>
            </td>
            <td>${a.remediation_action || "—"}</td>
            <td>
                <button class="btn-primary" 
                        style="font-size:11px; padding:6px 10px; background: var(--amber); border: none; color: #000; font-weight: 600;" 
                        onclick="dismissAlert('${a.id || a.pid}')">
                    Acquitter
                </button>
            </td>
        </tr>
    `;
    })
    .join("");

  tbody.innerHTML = `
        <table class="alert-table">
            <thead><tr>
                <th>Horodatage</th>
                <th>Hôte</th>
                <th>Processus</th>
                <th>Port</th>
                <th>Contexte & Détection</th>
                <th style="text-align: center;">Score de Risque</th>
                <th>Statut</th>
                <th>Remédiation</th>
                <th>Action</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
}

function renderVulnerabilitiesTable() {
  const tbody = document.getElementById("vulnerabilities-body");

  let data = allAlerts.filter(
    (a) => !a.resolved && a.process_name === "Vulnerability-Scanner",
  );

  if (!data.length) {
    tbody.innerHTML =
      '<div class="empty-state">Aucune vulnérabilité applicative détectée sur le parc.</div>';
    return;
  }

  const rows = data
    .map((a) => {
      const risk = a.risk_score !== undefined ? a.risk_score : 0;
      const riskColor =
        risk >= 60
          ? "var(--red)"
          : risk >= 30
            ? "var(--amber)"
            : "var(--green)";

      return `
        <tr id="row-vuln-${a.id}">
            <td style="white-space: nowrap;">${new Date(a.timestamp).toLocaleString("fr-FR")}</td>
            <td><strong>${a.hostname}</strong></td>
            <td><span class="badge badge-anomaly" style="background: rgba(239, 68, 68, 0.15); color: var(--red);">CVE / OSV</span></td>
            <td>
                <div style="max-width:450px; word-wrap:break-word; font-family: var(--font-mono); font-size:12px;" title="${a.alert_message}">
                    ${a.alert_message}
                </div>
            </td>
            <td style="text-align: center;">
                <div style="font-weight: 800; font-size: 14px; color: ${riskColor};">${risk}/100</div>
            </td>
            <td style="color: var(--text-primary); font-weight: 500;">${a.remediation_action || "Mettre à jour via apt/pip/npm"}</td>
            <td>
                <button class="btn-primary" 
                        style="font-size:11px; padding:6px 10px; background: var(--green); border: none; color: #fff; font-weight: 600;" 
                        onclick="dismissAlert('${a.id}')">
                    Mise à jour faite
                </button>
            </td>
        </tr>
    `;
    })
    .join("");

  tbody.innerHTML = `
        <table class="alert-table">
            <thead><tr>
                <th>Détection</th>
                <th>Serveur ciblé</th>
                <th>Type</th>
                <th>Composant & CVE Détectées</th>
                <th style="text-align: center;">Sévérité</th>
                <th>Action corrective</th>
                <th>Résolution</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
}

async function dismissAlert(alertIdentifier) {
  const alertIndex = allAlerts.findIndex(
    (a) => a.id == alertIdentifier || a.pid == alertIdentifier,
  );
  if (alertIndex === -1) return;

  const targetAlert = allAlerts[alertIndex];

  if (
    !confirm(
      `Confirmer l'acquittement de l'alerte pour le processus ${targetAlert.process_name || "sélectionné"} ?`,
    )
  )
    return;

  allAlerts.splice(alertIndex, 1);

  renderAll();

  document.getElementById("m-last-action").textContent = `Alerte clôturée`;
  document.getElementById("m-last-time").textContent =
    new Date().toLocaleTimeString("fr-FR");

  let currentAnomalies = parseInt(
    document.getElementById("m-anomalies").textContent,
  );
  if (!isNaN(currentAnomalies) && currentAnomalies > 0) {
    document.getElementById("m-anomalies").textContent = currentAnomalies - 1;
  }

  try {
    const resp = await fetch(
      `${API_BASE}/api/alerts/${alertIdentifier}/resolve`,
      {
        method: "PATCH",
      },
    );
    if (!resp.ok) throw new Error("Échec de l'acquittement");
  } catch (e) {
    console.warn(
      "Échec de la persistance côté serveur, l'alerte pourrait réapparaître au prochain rafraîchissement.",
    );
  }
}
function renderCharts() {
  const hostCounts = {};
  allAlerts.forEach((a) => {
    hostCounts[a.hostname] = (hostCounts[a.hostname] || 0) + 1;
  });
  const hostLabels = Object.keys(hostCounts);
  const hostData = Object.values(hostCounts);

  if (charts.hosts) charts.hosts.destroy();
  const ctx1 = document.getElementById("chartHosts").getContext("2d");
  charts.hosts = new Chart(ctx1, {
    type: "bar",
    data: {
      labels: hostLabels,
      datasets: [{ data: hostData, backgroundColor: "#3b82f6" }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
    },
  });

  const hourCounts = {};
  allAlerts
    .filter((a) => a.is_anomaly)
    .forEach((a) => {
      const h = new Date(a.timestamp).getHours();
      hourCounts[h] = (hourCounts[h] || 0) + 1;
    });
  const hours = Array.from({ length: 24 }, (_, i) => `${i}h`);
  const anomalyData = hours.map((_, i) => hourCounts[i] || 0);

  if (charts.timeline) charts.timeline.destroy();
  const ctx2 = document.getElementById("chartTimeline").getContext("2d");
  charts.timeline = new Chart(ctx2, {
    type: "line",
    data: {
      labels: hours,
      datasets: [{ data: anomalyData, borderColor: "#ef4444", tension: 0.3 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
    },
  });

  document.getElementById("last-refresh").textContent =
    `Mis à jour ${new Date().toLocaleTimeString("fr-FR")}`;
}

function renderAll() {
  renderAlertsTable();
  renderVulnerabilitiesTable();
  renderCharts();
}
refreshDashboard();
setInterval(refreshDashboard, 30000);
