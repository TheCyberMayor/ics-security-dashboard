// ICS Security Risk Dashboard - Enhanced with Backend Integration
// Connects to the comprehensive cybersecurity framework backend

// Authentication Management
class DashboardAuth {
  constructor() {
    this.sessionKey = 'ics_security_session';
    this.init();
  }

  init() {
    // Check authentication on page load
    if (!this.checkAuthentication()) {
      this.redirectToLogin();
      return;
    }
    
    // Setup user interface
    this.setupUserInterface();
    
    // Setup logout handler
    this.setupLogoutHandler();
  }

  checkAuthentication() {
    const session = this.getSession();
    if (!session || !this.isSessionValid(session)) {
      return false;
    }
    
    // Check if user has permission to access dashboard
    const user = session.user;
    if (!user || !user.permissions) {
      return false;
    }
    
    // All roles can access dashboard with different permission levels
    const hasAccess = user.permissions.includes('full_access') ||
                     user.permissions.includes('monitor_systems') ||
                     user.permissions.includes('system_analysis') ||
                     user.permissions.includes('read_only');
    
    return hasAccess;
  }

  getSession() {
    const sessionData = sessionStorage.getItem(this.sessionKey) || 
                       localStorage.getItem(this.sessionKey);
    
    if (sessionData) {
      try {
        return JSON.parse(sessionData);
      } catch (e) {
        console.error('Error parsing session data:', e);
        this.clearSession();
      }
    }
    return null;
  }

  isSessionValid(session) {
    if (!session || !session.expires) {
      return false;
    }
    
    const expiryTime = new Date(session.expires);
    const now = new Date();
    
    return now < expiryTime;
  }

  clearSession() {
    sessionStorage.removeItem(this.sessionKey);
    localStorage.removeItem(this.sessionKey);
  }

  redirectToLogin() {
    window.location.href = './login.html';
  }

  setupUserInterface() {
    const session = this.getSession();
    if (!session || !session.user) return;

    const user = session.user;
    const userInfo = document.getElementById('userInfo');
    const userName = document.getElementById('userName');
    const userRole = document.getElementById('userRole');

    if (userInfo && userName && userRole) {
      userName.textContent = user.displayName || user.username;
      userRole.textContent = user.role;
      userInfo.style.display = 'flex';
    }
  }

  setupLogoutHandler() {
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', () => {
        this.logout();
      });
    }
  }

  logout() {
    this.clearSession();
    this.redirectToLogin();
  }

  hasPermission(permission) {
    const session = this.getSession();
    if (session && session.user && session.user.permissions) {
      return session.user.permissions.includes(permission) || 
             session.user.permissions.includes('full_access');
    }
    return false;
  }

  getCurrentUser() {
    const session = this.getSession();
    return session ? session.user : null;
  }
}

// Initialize authentication
const dashboardAuth = new DashboardAuth();

// Dashboard stability management
class DashboardStability {
  constructor() {
    this.intervals = new Set();
    this.timeouts = new Set();
    this.isStable = true;
  }
  
  addInterval(intervalId) {
    this.intervals.add(intervalId);
  }
  
  addTimeout(timeoutId) {
    this.timeouts.add(timeoutId);
  }
  
  cleanup() {
    console.log('🧹 Cleaning up dashboard intervals and timeouts...');
    this.intervals.forEach(id => clearInterval(id));
    this.timeouts.forEach(id => clearTimeout(id));
    this.intervals.clear();
    this.timeouts.clear();
  }
  
  stabilize() {
    if (!this.isStable) {
      console.log('🔧 Stabilizing dashboard...');
      this.cleanup();
      this.isStable = true;
    }
  }
}

const dashboardStability = new DashboardStability();

// Configuration
const CONFIG = {
  API_BASE: window.location.hostname === 'localhost' && window.location.port === '8000' 
    ? 'http://localhost:8000/api' 
    : '/api',
  WS_URL: window.location.hostname === 'localhost' && window.location.port === '8000'
    ? 'ws://localhost:8000/ws'
    : `ws://${window.location.host}/ws`,
  UPDATE_INTERVAL: 15000, // Increased to 15 seconds to reduce blinking
  DEMO_MODE: true // Falls back to demo data if backend unavailable
};

// WebSocket connection for real-time updates
let websocket = null;
let backendAvailable = false;

// Utilities
function rand(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function lerp(a, b, t) { return a + (b - a) * t; }
function nowTs() { return Date.now(); }

// Color scale for risk: 0-100
function riskColor(score) {
  if (score >= 80) return '#ef4444'; // critical
  if (score >= 60) return '#f59e0b'; // high
  if (score >= 40) return '#eab308'; // medium
  return '#22c55e'; // low
}

// Fake data generator
const zones = ['IT', 'DMZ', 'OT', 'PLC'];
const nodeTemplates = [
  { type: 'PLC', group: 'PLC' },
  { type: 'HMI', group: 'OT' },
  { type: 'SCADA', group: 'OT' },
  { type: 'DB', group: 'IT' },
  { type: 'FW', group: 'DMZ' },
  { type: 'Hist', group: 'OT' },
];

function generateTopology(N = 18) {
  const nodes = [];
  const edges = [];
  for (let i = 0; i < N; i++) {
    const tmpl = nodeTemplates[rand(0, nodeTemplates.length - 1)];
    const risk = rand(10, 95);
    nodes.push({
      id: i + 1,
      label: `${tmpl.type}-${i + 1}`,
      title: `${tmpl.type}\nZone: ${tmpl.group}\nRisk: ${risk}`,
      zone: tmpl.group,
      risk,
      shape: 'dot',
      size: lerp(8, 28, risk / 100),
      color: { background: riskColor(risk), border: '#1f2937' },
      font: { color: '#e5e7eb', size: 14 },
    });
  }
  // Prefer connecting by proximity of index for a readable graph
  let edgeId = 1;
  for (let i = 2; i <= N; i++) {
    const from = rand(1, i - 1);
    edges.push({ id: edgeId++, from, to: i, color: { color: '#334155' } });
    if (Math.random() < 0.25) {
      const extra = rand(1, N);
      if (extra !== i && extra !== from) edges.push({ id: edgeId++, from: i, to: extra, dashes: true, color: { color: '#334155' } });
    }
  }
  return { nodes, edges };
}

// Alerts data
const severities = ['low', 'medium', 'high', 'critical'];
function generateAlert(id) {
  const sev = severities[rand(0, severities.length - 1)];
  const z = zones[rand(0, zones.length - 1)];
  const titles = {
    low: 'Baseline deviation detected',
    medium: 'Unauthorized software identified',
    high: 'Lateral movement suspected',
    critical: 'PLC overwrite attempt blocked',
  };
  const ts = nowTs() - rand(0, 1000 * 60 * 60 * 6); // within last 6h
  return {
    id,
    title: titles[sev],
    severity: sev,
    zone: z,
    ts,
  };
}

// State
const state = {
  topology: generateTopology(),
  alerts: Array.from({ length: 18 }, (_, i) => generateAlert(i + 1)),
  filters: { timeRange: '6h', severity: 'all', zone: 'all' },
};

// DOM refs
const el = (id) => document.getElementById(id);

// Initialize Topology (vis-network)
let network;
let nodeDS, edgeDS; // global datasets
let originalNodeColors = new Map();
let hierarchical = false;
function initTopology() {
  const container = el('topology');
  nodeDS = new vis.DataSet(state.topology.nodes);
  edgeDS = new vis.DataSet(state.topology.edges);
  // cache original colors for reset after filters
  state.topology.nodes.forEach(n => originalNodeColors.set(n.id, n.color));
  const data = { nodes: nodeDS, edges: edgeDS };
  const options = {
    physics: { stabilization: true },
    layout: { improvedLayout: true },
    interaction: { dragNodes: true, zoomView: true, dragView: true, hover: true },
    nodes: { borderWidth: 2 },
    edges: { smooth: { type: 'dynamic' } },
  };
  network = new vis.Network(container, data, options);

  network.on('click', (params) => {
    if (params.nodes.length) {
      const nodeId = params.nodes[0];
      const node = state.topology.nodes.find((n) => n.id === nodeId);
      drillDownNode(node);
    }
  });
}

function drillDownNode(node) {
  if (!node) return;
  const details = `
    <div class="detail">
      <h4>${node.label}</h4>
      <div class="kv"><span>Zone</span><span>${node.zone}</span></div>
      <div class="kv"><span>Risk</span><span style="color:${riskColor(node.risk)}">${node.risk}</span></div>
      <div class="kv"><span>Last Update</span><span>${new Date().toLocaleTimeString()}</span></div>
      <div class="kv"><span>Recent Alerts</span><span>${state.alerts.filter(a=>a.zone===node.zone).length}</span></div>
    </div>`;
  el('alertDetails').innerHTML = details;
}

// map numeric risk to severity bucket used by alerts filter
function sevFromRisk(risk) {
  if (risk >= 80) return 'critical';
  if (risk >= 60) return 'high';
  if (risk >= 40) return 'medium';
  return 'low';
}

// Toggle layout
function toggleLayout() {
  hierarchical = !hierarchical;
  network.setOptions({
    layout: hierarchical
      ? { hierarchical: { direction: 'LR', levelSeparation: 130, nodeSpacing: 100 } }
      : { hierarchical: false, improvedLayout: true },
    physics: { enabled: !hierarchical },
  });
}

// Fit graph
function fitGraph() { network && network.fit({ animation: true }); }

// Chart.js - Real-time Risk Timeline
let riskChart;
function initRiskTimeline() {
  const ctx = el('riskTimeline');
  const points = Array.from({ length: 30 }, (_, i) => ({ x: new Date(Date.now() - (29 - i) * 10000), y: 40 + Math.random() * 50 }));
  riskChart = new Chart(ctx, {
    type: 'line',
    data: {
      datasets: [{
        label: 'Risk score',
        data: points,
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56,189,248,0.12)',
        fill: true,
        tension: 0.25,
        pointRadius: 0,
      }],
    },
    options: {
      parsing: false,
      animation: false,
      responsive: true,
      scales: {
        x: { type: 'time', time: { unit: 'minute', displayFormats: { minute: 'HH:mm' } }, grid: { color: '#1f2937' }, ticks: { color: '#9ca3af' } },
        y: { min: 0, max: 100, grid: { color: '#1f2937' }, ticks: { color: '#9ca3af' } },
      },
      plugins: { legend: { labels: { color: '#e5e7eb' } } },
    },
  });
}

// Add new point every 10s (reduced frequency to prevent blinking)
let riskFeedInterval = null;
function startRiskFeed() {
  if (riskFeedInterval) clearInterval(riskFeedInterval);
  riskFeedInterval = setInterval(() => {
    if (!riskChart) return;
    const ds = riskChart.data.datasets[0];
    const last = ds.data[ds.data.length - 1]?.y ?? 60;
    const next = Math.max(0, Math.min(100, last + rand(-2, 3))); // Smaller changes
    ds.data.push({ x: new Date(), y: next });
    while (ds.data.length > 60) ds.data.shift();
    riskChart.update('none');
    el('overallRisk').textContent = Math.round(next);
  }, 10000); // Reduced from 2s to 10s
}

// Attack Distribution Pie
let attackPie;
function initAttackPie() {
  const ctx = el('attackPie');
  const labels = ['Malware', 'Phishing', 'Brute Force', 'Misconfig', 'Zero-day'];
  const values = labels.map(() => rand(5, 25));
  attackPie = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: ['#22c55e', '#38bdf8', '#f59e0b', '#eab308', '#ef4444'],
        borderColor: '#0b1220',
      }],
    },
    options: {
      plugins: { legend: { position: 'bottom', labels: { color: '#e5e7eb' } } },
      onClick: (e, els) => {
        const idx = els[0]?.index;
        if (idx != null) filterByAttack(labels[idx]);
      },
    },
  });
}

function filterByAttack(type) {
  // Placeholder interaction: show detail message
  el('alertDetails').innerHTML = `<div class="detail"><h4>Attack: ${type}</h4><p>Filtering alerts and nodes associated with ${type} (demo).</p></div>`;
}

// Alerts rendering and interactions
function renderAlerts() {
  const list = el('alertsList');
  const f = state.filters;
  const horizonMs = rangeToMs(f.timeRange);
  const now = nowTs();
  const filtered = state.alerts.filter(a =>
    (f.severity === 'all' || a.severity === f.severity) &&
    (f.zone === 'all' || a.zone === f.zone) &&
    (now - a.ts <= horizonMs)
  );
  el('openAlerts').textContent = filtered.length.toString();
  list.innerHTML = filtered.map(a => `
    <div class="alert" data-id="${a.id}">
      <div class="checkbox"><input type="checkbox" class="selectAlert" data-id="${a.id}"></div>
      <div>
        <div class="title">${a.title}</div>
        <div class="meta">${new Date(a.ts).toLocaleTimeString()} • ${a.zone}</div>
      </div>
      <div class="sev ${a.severity}">${a.severity}</div>
    </div>`).join('');

  list.querySelectorAll('.alert').forEach(item => {
    item.addEventListener('click', (e) => {
      if (e.target.closest('input')) return; // ignore checkbox clicks
      const id = Number(item.getAttribute('data-id'));
      const alert = state.alerts.find(a => a.id === id);
      showAlertDetail(alert);
    });
  });
}

function showAlertDetail(alert) {
  if (!alert) return;
  const html = `
    <div class="detail">
      <h4>${alert.title}</h4>
      <div class="kv"><span>Severity</span><span class="sev ${alert.severity}">${alert.severity}</span></div>
      <div class="kv"><span>Zone</span><span>${alert.zone}</span></div>
      <div class="kv"><span>Time</span><span>${new Date(alert.ts).toLocaleString()}</span></div>
      <div class="kv"><span>Recommended Action</span><span>${recommendation(alert)}</span></div>
      <div class="actions"><button class="btn" onclick="ackAlert(${alert.id})">Acknowledge</button> <button class="btn" onclick="suppressAlert(${alert.id})">Suppress</button></div>
    </div>`;
  el('alertDetails').innerHTML = html;
}

function recommendation(alert) {
  switch (alert.severity) {
    case 'critical': return 'Isolate affected PLC segment; block write operations; escalate incident.';
    case 'high': return 'Limit lateral movement via ACLs; increase monitoring; patch vulnerable nodes.';
    case 'medium': return 'Verify software inventory; remove unauthorized tools; review access logs.';
    default: return 'Monitor and verify baseline changes in the next 24 hours.';
  }
}

// Alert actions
function getSelectedAlertIds() {
  return Array.from(document.querySelectorAll('.selectAlert:checked')).map(cb => Number(cb.getAttribute('data-id')));
}
function ackAlert(id) { console.log('Ack alert', id); }
function suppressAlert(id) { console.log('Suppress alert', id); }

// Bulk actions
function bulkAck() { getSelectedAlertIds().forEach(ackAlert); }
function bulkSuppress() { getSelectedAlertIds().forEach(suppressAlert); }
function exportAlerts() {
  const rows = [['id','title','severity','zone','time'], ...state.alerts.map(a => [a.id,a.title,a.severity,a.zone,new Date(a.ts).toISOString()])];
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g,'""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'alerts.csv'; a.click(); URL.revokeObjectURL(url);
}

// Filters
function applyFilters() {
  state.filters = {
    timeRange: el('timeRange').value,
    severity: el('severity').value,
    zone: el('zone').value,
  };
  renderAlerts();
  // Visual filtering on topology: dim non-matching nodes/edges
  const { severity, zone } = state.filters;
  const matchNode = (n) => (zone === 'all' || n.zone === zone) && (severity === 'all' || sevFromRisk(n.risk) === severity);
  const updates = [];
  nodeDS.forEach(n => {
    const matched = matchNode(n);
    const base = originalNodeColors.get(n.id) || n.color;
    updates.push({ id: n.id, color: matched ? base : { background: '#1f2937', border: '#1f2937' } });
  });
  nodeDS.update(updates);
  // edges: dim if either endpoint is dimmed
  const nodeVisible = new Set();
  nodeDS.forEach(n => { if ((zone === 'all' || n.zone === zone) && (severity === 'all' || sevFromRisk(n.risk) === severity)) nodeVisible.add(n.id); });
  const edgeUpdates = [];
  edgeDS.forEach(e => {
    const vis = nodeVisible.has(e.from) && nodeVisible.has(e.to);
    edgeUpdates.push({ id: e.id, color: { color: vis ? '#334155' : '#111827' } });
  });
  if (edgeUpdates.length) edgeDS.update(edgeUpdates);
  // select and focus one matched node if any
  const ids = state.topology.nodes.filter(matchNode).map(n => n.id);
  if (ids.length) {
    network.selectNodes(ids.slice(0, 8));
    network.focus(ids[0], { scale: 1.2, animation: true });
  } else {
    network.unselectAll();
  }
}

// System Health: simple periodic changes
let healthTickerInterval = null;
function startHealthTicker() {
  if (healthTickerInterval) clearInterval(healthTickerInterval);
  const statuses = ['OK', 'Degraded', 'High Load', 'Maintenance'];
  healthTickerInterval = setInterval(() => {
    const plc = statuses[rand(0, 1)];
    const scada = statuses[rand(0, 2)];
    const hist = statuses[rand(0, 1)];
    const dmz = statuses[rand(2, 3)];
    el('health-plc').textContent = plc;
    el('health-scada').textContent = scada;
    el('health-historian').textContent = hist;
    el('health-dmz').textContent = dmz;
  }, 15000); // Increased from 8s to 15s
}

// Wire up UI
function initUI() {
  el('applyFilters').addEventListener('click', applyFilters);
  el('toggleLayout').addEventListener('click', toggleLayout);
  el('fitGraph').addEventListener('click', fitGraph);
  el('ackSelected').addEventListener('click', bulkAck);
  el('suppressSelected').addEventListener('click', bulkSuppress);
  el('exportAlerts').addEventListener('click', exportAlerts);
}

function rangeToMs(key) {
  switch (key) {
    case '1h': return 60 * 60 * 1000;
    case '6h': return 6 * 60 * 60 * 1000;
    case '24h': return 24 * 60 * 60 * 1000;
    case '7d': return 7 * 24 * 60 * 60 * 1000;
    default: return 6 * 60 * 60 * 1000;
  }
}

// Backend API Integration
async function checkBackendHealth() {
  try {
    const response = await fetch(`${CONFIG.API_BASE}/health`, { 
      method: 'GET',
      timeout: 5000 
    });
    if (response.ok) {
      const health = await response.json();
      backendAvailable = health.status === 'healthy';
      console.log('✓ Backend connected:', health);
      return true;
    }
  } catch (error) {
    console.warn('⚠ Backend unavailable, using demo mode:', error.message);
  }
  backendAvailable = false;
  return false;
}

async function fetchBackendData(endpoint) {
  if (!backendAvailable) return null;
  try {
    const response = await fetch(`${CONFIG.API_BASE}${endpoint}`);
    if (response.ok) {
      return await response.json();
    }
  } catch (error) {
    console.warn(`Backend fetch failed for ${endpoint}:`, error);
  }
  return null;
}

async function loadNetworkTopology() {
  const data = await fetchBackendData('/network/topology');
  if (data && data.nodes && data.edges) {
    // Update network with real backend data
    console.log('📊 Loaded real network topology:', data.nodes.length, 'nodes');
    
    // Convert backend format to vis.js format
    const nodes = data.nodes.map(node => ({
      id: node.id,
      label: node.label || node.id,
      title: `${node.type}\nZone: ${node.zone}\nRisk: ${(node.risk_score * 100).toFixed(1)}%`,
      zone: node.zone,
      risk: node.risk_score * 100,
      shape: 'dot',
      size: Math.max(8, node.size || (8 + node.risk_score * 20)),
      color: { background: node.color || riskColor(node.risk_score * 100), border: '#1f2937' },
      font: { color: '#e5e7eb', size: 14 }
    }));
    
    const edges = data.edges.map((edge, idx) => ({
      id: idx,
      from: edge.from,
      to: edge.to,
      color: { color: edge.encrypted ? '#4ade80' : '#334155' },
      dashes: !edge.encrypted,
      title: `Protocol: ${edge.protocol}\nEncrypted: ${edge.encrypted ? 'Yes' : 'No'}`
    }));
    
    // Update topology with real data
    nodeDS.clear();
    edgeDS.clear();
    nodeDS.add(nodes);
    edgeDS.add(edges);
    
    // Update original node colors cache
    originalNodeColors.clear();
    nodes.forEach(n => originalNodeColors.set(n.id, n.color));
    
    return { nodes, edges };
  }
  return null;
}

async function loadRealAlerts() {
  const data = await fetchBackendData('/alerts');
  if (data && data.alerts) {
    console.log('📋 Loaded real alerts:', data.alerts.length);
    
    // Convert backend alerts to frontend format
    state.alerts = data.alerts.map(alert => ({
      id: parseInt(alert.alert_id.replace(/\D/g, '')) || Math.random() * 1000,
      title: alert.title,
      severity: alert.severity,
      zone: alert.zone,
      ts: new Date(alert.timestamp).getTime()
    }));
    
    return true;
  }
  return false;
}

async function submitThreatToBackend(threatData) {
  if (!backendAvailable) return false;
  
  try {
    const response = await fetch(`${CONFIG.API_BASE}/threats`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        event_id: `UI_${Date.now()}`,
        timestamp: new Date().toISOString(),
        threat_level: threatData.severity || 'medium',
        attack_vector: threatData.attack_vector || 'Manual Submission',
        affected_assets: threatData.affected_assets || ['Unknown'],
        confidence: threatData.confidence || 0.8,
        potential_impact: threatData.impact || 0.6,
        source_ip: threatData.source_ip || 'unknown',
        target_systems: threatData.targets || ['ICS Network']
      })
    });
    
    if (response.ok) {
      const result = await response.json();
      console.log('✓ Threat submitted to backend:', result);
      return true;
    }
  } catch (error) {
    console.error('Failed to submit threat:', error);
  }
  return false;
}

function initWebSocket() {
  if (!backendAvailable) return;
  
  try {
    websocket = new WebSocket(CONFIG.WS_URL);
    
    websocket.onopen = () => {
      console.log('🔌 WebSocket connected');
      // Subscribe to updates
      websocket.send(JSON.stringify({ type: 'subscribe' }));
    };
    
    websocket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        handleRealtimeUpdate(data);
      } catch (error) {
        console.error('WebSocket message parse error:', error);
      }
    };
    
    websocket.onclose = () => {
      console.log('🔌 WebSocket disconnected, attempting reconnect...');
      setTimeout(initWebSocket, 5000);
    };
    
    websocket.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    // Keep connection alive
    setInterval(() => {
      if (websocket?.readyState === WebSocket.OPEN) {
        websocket.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000);
    
  } catch (error) {
    console.error('WebSocket initialization failed:', error);
  }
}

function handleRealtimeUpdate(data) {
  switch (data.type) {
    case 'metrics_update':
      if (data.data) {
        updateDashboardMetrics(data.data);
      }
      break;
      
    case 'new_threat':
      console.log('🚨 New threat detected:', data.threat);
      showThreatNotification(data.threat, data.mitigation);
      break;
      
    case 'mitigation_result':
      console.log('🛡️ Mitigation executed:', data);
      showMitigationResult(data);
      break;
      
    case 'initial_data':
      if (data.metrics) {
        updateDashboardMetrics(data.metrics);
      }
      break;
      
    case 'pong':
      // Keep-alive response
      break;
      
    default:
      console.log('Unknown WebSocket message:', data);
  }
}

function updateDashboardMetrics(metrics) {
  if (metrics.total_threats !== undefined) {
    el('openAlerts').textContent = metrics.active_threats || 0;
  }
  if (metrics.system_health !== undefined) {
    const healthPercent = Math.round(metrics.system_health * 100);
    el('systemsHealthy').textContent = `${healthPercent}%`;
  }
  if (metrics.mitigation_success_rate !== undefined) {
    // Could update a success rate display if we add one
  }
}

function showThreatNotification(threat, mitigation) {
  // Create notification
  const notification = document.createElement('div');
  notification.className = 'threat-notification';
  notification.innerHTML = `
    <div class="notification-content">
      <h4>🚨 Threat Detected</h4>
      <p><strong>${threat.attack_vector}</strong></p>
      <p>Level: <span class="sev ${threat.threat_level}">${threat.threat_level}</span></p>
      ${mitigation ? `<p>Action: <strong>${mitigation.action}</strong> (${(mitigation.success_rate * 100).toFixed(1)}% success rate)</p>` : ''}
    </div>
  `;
  
  // Add notification styles if not already present
  if (!document.querySelector('#threat-notification-styles')) {
    const styles = document.createElement('style');
    styles.id = 'threat-notification-styles';
    styles.textContent = `
      .threat-notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--panel);
        border: 1px solid var(--border);
        border-left: 4px solid var(--red);
        border-radius: 8px;
        padding: 12px;
        max-width: 300px;
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
      }
      @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      .notification-content h4 {
        margin: 0 0 8px;
        color: var(--text);
      }
      .notification-content p {
        margin: 4px 0;
        color: var(--muted);
        font-size: 14px;
      }
    `;
    document.head.appendChild(styles);
  }
  
  document.body.appendChild(notification);
  
  // Remove after 5 seconds
  setTimeout(() => {
    if (notification.parentNode) {
      notification.remove();
    }
  }, 5000);
}

function showMitigationResult(data) {
  console.log('Mitigation result:', data);
  // Update alert details if this threat is selected
  const currentDetail = el('alertDetails').innerHTML;
  if (currentDetail.includes(data.threat_id)) {
    el('alertDetails').innerHTML += `<div class="mitigation-update">🛡️ Action taken: <strong>${data.action}</strong></div>`;
  }
}

// Enhanced functions with backend fallback
async function loadEnhancedData() {
  console.log('🔄 Loading enhanced data...');
  
  // Try to load real network topology
  const topologyLoaded = await loadNetworkTopology();
  if (!topologyLoaded && CONFIG.DEMO_MODE) {
    console.log('📊 Using demo network topology');
    // Keep existing demo data
  }
  
  // Try to load real alerts
  const alertsLoaded = await loadRealAlerts();
  if (!alertsLoaded && CONFIG.DEMO_MODE) {
    console.log('📋 Using demo alerts');
    // Keep existing demo data
  }
  
  // Render alerts with updated data
  renderAlerts();
}

// Periodic data refresh
let dataRefreshInterval = null;
function startDataRefresh() {
  if (dataRefreshInterval) clearInterval(dataRefreshInterval);
  dataRefreshInterval = setInterval(async () => {
    if (backendAvailable) {
      await loadEnhancedData();
    }
  }, CONFIG.UPDATE_INTERVAL);
}

// Boot sequence
window.addEventListener('DOMContentLoaded', async () => {
  console.log('🚀 Initializing ICS Security Dashboard...');
  
  // Initialize core components
  initTopology();
  initRiskTimeline();
  initAttackPie();
  initUI();
  
  // Check backend availability
  await checkBackendHealth();
  
  // Load enhanced data if backend available
  if (backendAvailable) {
    await loadEnhancedData();
    initWebSocket();
    startDataRefresh();
    console.log('✅ Enhanced mode: Connected to cybersecurity framework backend');
  } else {
    console.log('📊 Demo mode: Using simulated data');
  }
  
  // Start demo feeds (will be enhanced by real data if available)
  renderAlerts();
  startRiskFeed();
  startHealthTicker();
  
  console.log('🔒 Dashboard initialization complete');
});
