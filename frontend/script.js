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
    const resp = await fetch(`${API_BASE}/api/alerts/?limit=100`);
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
  let data = allAlerts;

  if (currentFilter === "anomalie")
    data = allAlerts.filter((a) => a.is_anomaly);
  else if (currentFilter === "port")
    data = allAlerts.filter((a) => a.port === 4444 || a.port === 1337);

  if (!data.length) {
    tbody.innerHTML =
      '<div class="empty-state">Aucune alerte à afficher.</div>';
    return;
  }

  const rows = data
    .slice(0, 30)
    .map((a) => {
      const isResolved = a.resolved;

      return `
        <tr class="${isResolved ? "row-resolved" : ""}" id="row-${a.pid}">
            <td>${new Date(a.timestamp).toLocaleString("fr-FR")}</td>
            <td><strong>${a.hostname}</strong></td>
            <td>${a.process_name}</td>
            <td>PID ${a.pid}</td>
            <td><span class="badge badge-port">:${a.port}</span></td>
            <td class="alert-msg" style="max-width:200px; overflow:hidden; text-overflow:ellipsis;" title="${a.alert_message}">${a.alert_message}</td>
            <td>
                <span id="badge-${a.pid}" class="badge ${isResolved ? "badge-resolved" : a.is_anomaly ? "badge-anomaly" : "badge-normal"}">
                    ${isResolved ? "✓ Mitigé" : a.is_anomaly ? "Anomalie" : "Normal"}
                </span>
            </td>
            <td>${a.remediation_action || "—"}</td>
            <td>
                ${a.is_anomaly ? `<button id="btn-${a.pid}" class="btn-primary ${isResolved ? "btn-disabled" : ""}" style="font-size:11px; padding:4px 8px;" onclick="killProcess('${a.pid}', '${a.hostname}')" ${isResolved ? "disabled" : ""}>${isResolved ? "Résolu" : "Kill"}</button>` : ""}
            </td>
        </tr>
    `;
    })
    .join("");

  tbody.innerHTML = `
        <table class="alert-table">
            <thead><tr>
                <th>Horodatage</th><th>Hôte</th><th>Processus</th><th>PID</th><th>Port</th><th>Message</th><th>Statut</th><th>Remédiation</th><th>Action</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
}

async function killProcess(pid, hostname) {
  if (
    !confirm(
      `Confirmer la destruction du processus suspect PID ${pid} sur ${hostname} ?`,
    )
  )
    return;

  const btn = document.getElementById(`btn-${pid}`);
  btn.textContent = "En cours...";
  btn.classList.add("btn-disabled");

  try {
    const resp = await fetch(
      `${API_BASE}/api/actions/kill/${pid}?hostname=${hostname}`,
      { method: "POST" },
    );

    if (resp.ok) {
      const targetAlert = allAlerts.find((a) => a.pid == pid);
      if (targetAlert) targetAlert.resolved = true;

      document.getElementById(`row-${pid}`).classList.add("row-resolved");

      const badge = document.getElementById(`badge-${pid}`);
      badge.className = "badge badge-resolved";
      badge.textContent = "✓ Mitigé";

      btn.textContent = "Résolu";
      btn.disabled = true;

      document.getElementById("m-last-action").textContent =
        `PID ${pid} neutralisé`;
      document.getElementById("m-last-time").textContent =
        new Date().toLocaleTimeString();

      let currentAnomalies = parseInt(
        document.getElementById("m-anomalies").textContent,
      );
      if (!isNaN(currentAnomalies) && currentAnomalies > 0) {
        document.getElementById("m-anomalies").textContent =
          currentAnomalies - 1;
      }
    } else {
      throw new Error("API refusée");
    }
  } catch (e) {
    alert(
      `Échec de la remédiation pour le PID ${pid}. Vérifiez la connexion Wazuh.`,
    );
    btn.textContent = "Kill";
    btn.classList.remove("btn-disabled");
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
  renderCharts();
}

refreshDashboard();
setInterval(refreshDashboard, 30000);
