const API = 'http://localhost:8000/api/alerts/';
let allAlerts = [];
let currentFilter = 'all';
let chartPort, chartTime;

const SENSITIVE = { 22:'SSH', 3306:'MySQL', 8080:'HTTP alt', 4444:'Metasploit' };
const CRITICAL = [4444];

function severity(port) {
  if (CRITICAL.includes(port)) return 'danger';
  if (SENSITIVE[port]) return 'warning';
  return 'info';
}

function sevLabel(port) {
  if (CRITICAL.includes(port)) return 'critique';
  if (SENSITIVE[port]) return 'sensible';
  return 'info';
}

function fmt(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString('fr-FR', {day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
}

function timeDiff(ts) {
  if (!ts) return '';
  const diff = Math.floor((Date.now() - new Date(ts)) / 60000);
  if (diff < 1) return 'à l\'instant';
  if (diff < 60) return `il y a ${diff} min`;
  return `il y a ${Math.floor(diff/60)}h`;
}

async function fetchAlerts() {
  try {
    const r = await fetch(API, { signal: AbortSignal.timeout(4000) });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    allAlerts = await r.json();
    setApiStatus(true);
    updateMetrics();
    renderTable();
    renderCharts();
    document.getElementById('last-refresh').textContent = 'Mis à jour ' + new Date().toLocaleTimeString('fr-FR');
  } catch(e) {
    setApiStatus(false, e.message);
    if (!allAlerts.length) {
      document.getElementById('alerts-body').innerHTML = '<div class="empty-state">Impossible de joindre le backend.<br><span style="font-size:12px; margin-top: 8px; display: block;">Vérifiez que FastAPI tourne sur localhost:8000</span></div>';
    }
  }
}

function setApiStatus(ok, err) {
  document.getElementById('status-dot').className = 'status-dot ' + (ok ? 'green' : 'red');
  document.getElementById('status-text').textContent = ok ? 'Backend connecté' : 'Backend hors ligne';
}

function updateMetrics() {
  const total = allAlerts.length;
  const critical = allAlerts.filter(a => CRITICAL.includes(a.port)).length;
  const sensitive = allAlerts.filter(a => SENSITIVE[a.port] && !CRITICAL.includes(a.port)).length;
  const procs = new Set(allAlerts.map(a => a.process_name)).size;
  
  document.getElementById('m-total').textContent = total;
  document.getElementById('m-critical').textContent = critical;
  document.getElementById('m-sensitive').textContent = sensitive;
  document.getElementById('m-procs').textContent = procs;
  
  if (allAlerts.length) {
    const last = allAlerts[0];
    document.getElementById('m-last').textContent = `:${last.port}`;
    document.getElementById('m-last-sub').textContent = timeDiff(last.timestamp);
  }
}

function setFilter(f, el) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  renderTable();
}

function renderTable() {
  const data = currentFilter === 'all' ? allAlerts : allAlerts.filter(a => String(a.port) === currentFilter);
  
  if (!data.length) {
    document.getElementById('alerts-body').innerHTML = '<div class="empty-state">Aucune alerte pour ce filtre.</div>';
    return;
  }
  
  const rows = data.slice(0, 50).map(a => {
    const sev = severity(a.port);
    const lbl = sevLabel(a.port);
    return `<tr>
      <td style="color:var(--color-text-tertiary);font-family:var(--font-mono);">${fmt(a.timestamp)}</td>
      <td><code style="font-family:var(--font-mono);">${a.process_name}</code></td>
      <td style="color:var(--color-text-secondary);font-family:var(--font-mono);">${a.pid}</td>
      <td><span class="port-pill">:${a.port}</span></td>
      <td><span class="badge badge-${sev}">${lbl}</span></td>
      <td style="color:var(--color-text-secondary);max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.alert_message}">${a.alert_message}</td>
    </tr>`;
  }).join('');
  
  document.getElementById('alerts-body').innerHTML = `
    <table class="alert-table">
      <thead><tr>
        <th>Horodatage</th><th>Processus</th><th>PID</th><th>Port</th><th>Sévérité</th><th>Message</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderCharts() {
  const portCounts = {};
  const hourCounts = {};
  
  allAlerts.forEach(a => {
    portCounts[a.port] = (portCounts[a.port]||0)+1;
    if (a.timestamp) {
      const h = new Date(a.timestamp).getHours();
      hourCounts[h] = (hourCounts[h]||0)+1;
    }
  });

  const portLabels = Object.keys(portCounts).map(p => `:${p} ${SENSITIVE[p]||''}`);
  const portData = Object.values(portCounts);
  const portColors = Object.keys(portCounts).map(p => CRITICAL.includes(parseInt(p)) ? '#E24B4A' : '#1D9E75');

  const ctx1 = document.getElementById('chartPort');
  if (chartPort) chartPort.destroy();
  chartPort = new Chart(ctx1, {
    type: 'bar',
    data: { 
      labels: portLabels, 
      datasets: [{ label: 'Alertes', data: portData, backgroundColor: portColors, borderRadius: 4 }] 
    },
    options: {
      responsive: true, 
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { font: { family: "'Fira Code', monospace", size: 11 }, color: '#888' }, grid: { display: false } },
        y: { ticks: { font: { family: "'Fira Code', monospace", size: 11 }, color: '#888', stepSize: 1 }, grid: { color: 'rgba(128,128,128,0.1)' } }
      }
    }
  });

  const hours = Array.from({length:24},(_,i)=>i);
  const timeData = hours.map(h => hourCounts[h]||0);
  const ctx2 = document.getElementById('chartTime');
  
  if (chartTime) chartTime.destroy();
  chartTime = new Chart(ctx2, {
    type: 'line',
    data: {
      labels: hours.map(h => `${String(h).padStart(2,'0')}h`),
      datasets: [{ 
        label: 'Alertes/h', 
        data: timeData, 
        borderColor: '#1D9E75', 
        backgroundColor: 'rgba(29,158,117,0.1)', 
        tension: 0.3, 
        fill: true, 
        pointRadius: 2,
        borderWidth: 2
      }]
    },
    options: {
      responsive: true, 
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { font: { family: "'Fira Code', monospace", size: 10 }, color: '#888', maxTicksLimit: 8, autoSkip: true }, grid: { display: false } },
        y: { ticks: { font: { family: "'Fira Code', monospace", size: 11 }, color: '#888', stepSize: 1 }, grid: { color: 'rgba(128,128,128,0.1)' } }
      }
    }
  });
}

async function sendAlert() {
  const btn = document.getElementById('btn-send');
  const st = document.getElementById('send-status');
  btn.disabled = true; 
  btn.textContent = 'Envoi...';
  
  const payload = {
    process_name: document.getElementById('f-proc').value,
    pid: document.getElementById('f-pid').value,
    port: parseInt(document.getElementById('f-port').value),
    alert_message: document.getElementById('f-msg').value
  };
  
  try {
    const r = await fetch(API, { 
      method:'POST', 
      headers:{'Content-Type':'application/json'}, 
      body: JSON.stringify(payload), 
      signal: AbortSignal.timeout(5000) 
    });
    
    if (r.status === 201 || r.status === 200) {
      st.textContent = '✓ Alerte envoyée'; 
      st.style.color = '#1D9E75';
      setTimeout(() => fetchAlerts(), 500);
    } else {
      st.textContent = `Erreur HTTP ${r.status}`; 
      st.style.color = '#E24B4A';
    }
  } catch(e) {
    st.textContent = 'Backend inaccessible'; 
    st.style.color = '#E24B4A';
  }
  
  btn.disabled = false; 
  btn.textContent = 'Envoyer l\'alerte au backend →';
  setTimeout(() => { st.textContent = ''; }, 4000);
}

// Initial fetch on page load
fetchAlerts();