// ICS Security Dashboard - STABLE VERSION
// No automatic updates to prevent blinking

console.log('🚀 Loading STABLE ICS Security Dashboard...');

// Static configuration - no auto-updates
const CONFIG = {
  STABLE_MODE: true,
  AUTO_UPDATE: false,
  DEMO_MODE: true
};

// Initialize authentication (keep existing auth)
const dashboardAuth = window.dashboardAuth || {
  getCurrentUser: () => ({ username: 'demo', role: 'User' }),
  hasPermission: () => true
};

// Static data - no changes
const staticTopologyData = {
  nodes: [
    {id: 'PLC-01', label: 'PLC-01', group: 'plc', risk: 72, x: 100, y: 100},
    {id: 'HMI-01', label: 'HMI-01', group: 'hmi', risk: 45, x: 200, y: 150},
    {id: 'SCADA', label: 'SCADA', group: 'scada', risk: 63, x: 300, y: 100},
    {id: 'FW-01', label: 'Firewall', group: 'firewall', risk: 28, x: 400, y: 200},
    {id: 'DB-01', label: 'Database', group: 'database', risk: 35, x: 500, y: 150},
    {id: 'SW-01', label: 'Switch', group: 'switch', risk: 15, x: 150, y: 250},
    {id: 'RTU-01', label: 'RTU-01', group: 'rtu', risk: 55, x: 350, y: 300},
    {id: 'WS-01', label: 'Workstation', group: 'workstation', risk: 40, x: 450, y: 50}
  ],
  edges: [
    {from: 'PLC-01', to: 'SW-01'},
    {from: 'HMI-01', to: 'SCADA'},
    {from: 'SCADA', to: 'FW-01'},
    {from: 'FW-01', to: 'DB-01'},
    {from: 'SW-01', to: 'SCADA'},
    {from: 'RTU-01', to: 'SCADA'},
    {from: 'WS-01', to: 'FW-01'}
  ]
};

// Static alerts - no changes
const staticAlerts = [
  {id: 1, title: 'High CPU Usage', severity: 'high', zone: 'PLC', time: '10:45 AM', status: 'active'},
  {id: 2, title: 'Network Anomaly', severity: 'medium', zone: 'DMZ', time: '10:30 AM', status: 'active'},
  {id: 3, title: 'Authentication Failed', severity: 'critical', zone: 'IT', time: '10:15 AM', status: 'acknowledged'},
  {id: 4, title: 'Memory Warning', severity: 'low', zone: 'OT', time: '10:00 AM', status: 'suppressed'}
];

// Global variables
let network = null;
let riskChart = null;
let attackChart = null;

// Utility functions
function el(id) { return document.getElementById(id); }
function riskColor(score) {
  if (score >= 80) return '#ef4444';
  if (score >= 60) return '#f59e0b'; 
  if (score >= 40) return '#eab308';
  return '#22c55e';
}

// Initialize network topology (static)
function initTopology() {
  console.log('📊 Initializing static network topology...');
  
  const container = el('topology');
  if (!container) {
    console.warn('Topology container not found');
    return;
  }

  const options = {
    nodes: {
      shape: 'dot',
      size: 20,
      font: { size: 12, color: '#ffffff' },
      borderWidth: 2,
      borderWidthSelected: 3
    },
    edges: {
      width: 2,
      color: { color: '#64748b', highlight: '#3b82f6' },
      smooth: { type: 'dynamic', roundness: 0.5 }
    },
    physics: {
      enabled: false // Static positioning
    },
    interaction: {
      hover: true,
      selectConnectedEdges: false
    }
  };

  // Process nodes with colors
  const nodes = staticTopologyData.nodes.map(node => ({
    ...node,
    color: {
      background: riskColor(node.risk),
      border: '#1f2937'
    },
    title: `${node.label}<br>Risk: ${node.risk}/100`
  }));

  try {
    network = new vis.Network(container, {
      nodes: new vis.DataSet(nodes),
      edges: new vis.DataSet(staticTopologyData.edges)
    }, options);
    
    console.log('✅ Network topology initialized');
  } catch (error) {
    console.error('❌ Network topology failed:', error);
    container.innerHTML = '<p style="color: #64748b; text-align: center; padding: 40px;">Network visualization unavailable</p>';
  }
}

// Initialize risk timeline chart (static)
function initRiskChart() {
  console.log('📈 Initializing static risk chart...');
  
  const ctx = el('riskChart')?.getContext('2d');
  if (!ctx) {
    console.warn('Risk chart canvas not found');
    return;
  }

  // Static data points
  const now = new Date();
  const staticData = [];
  for (let i = 30; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 60000); // Every minute
    staticData.push({
      x: time,
      y: 65 + Math.sin(i * 0.3) * 10 + Math.random() * 5
    });
  }

  try {
    riskChart = new Chart(ctx, {
      type: 'line',
      data: {
        datasets: [{
          label: 'Overall Risk Score',
          data: staticData,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239, 68, 68, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: {
            type: 'time',
            time: { unit: 'minute' },
            grid: { color: '#374151' },
            ticks: { color: '#9ca3af' }
          },
          y: {
            min: 0,
            max: 100,
            grid: { color: '#374151' },
            ticks: { color: '#9ca3af' }
          }
        },
        plugins: {
          legend: { display: false }
        },
        animation: false // No animations to prevent blinking
      }
    });
    
    console.log('✅ Risk chart initialized');
  } catch (error) {
    console.error('❌ Risk chart failed:', error);
  }
}

// Initialize attack distribution chart (static)
function initAttackChart() {
  console.log('🎯 Initializing static attack chart...');
  
  const ctx = el('attackChart')?.getContext('2d');
  if (!ctx) {
    console.warn('Attack chart canvas not found');
    return;
  }

  try {
    attackChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Malware', 'Phishing', 'Network Intrusion', 'Insider Threat', 'Other'],
        datasets: [{
          data: [35, 25, 20, 15, 5],
          backgroundColor: ['#ef4444', '#f59e0b', '#eab308', '#06b6d4', '#64748b'],
          borderColor: '#1f2937',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#d1d5db', padding: 15 }
          }
        },
        animation: false // No animations
      }
    });
    
    console.log('✅ Attack chart initialized');
  } catch (error) {
    console.error('❌ Attack chart failed:', error);
  }
}

// Render alerts (static)
function renderAlerts() {
  console.log('🚨 Rendering static alerts...');
  
  const container = el('alertsList');
  if (!container) return;

  container.innerHTML = staticAlerts.map(alert => `
    <div class="alert ${alert.status}" style="border-left-color: ${
      alert.severity === 'critical' ? '#ef4444' :
      alert.severity === 'high' ? '#f59e0b' :
      alert.severity === 'medium' ? '#eab308' : '#22c55e'
    }">
      <div class="checkbox">
        <input type="checkbox" ${alert.status === 'acknowledged' ? 'checked' : ''}>
      </div>
      <div>
        <div class="title">${alert.title}</div>
        <div class="meta">${alert.zone} • ${alert.time}</div>
      </div>
      <div class="sev ${alert.severity}">${alert.severity}</div>
    </div>
  `).join('');
}

// Set static values
function setStaticValues() {
  console.log('🔢 Setting static dashboard values...');
  
  // Static metrics
  if (el('overallRisk')) el('overallRisk').textContent = '72';
  if (el('systemsHealthy')) el('systemsHealthy').textContent = '18/22';
  if (el('openAlerts')) el('openAlerts').textContent = '12';
  if (el('avgMTTD')) el('avgMTTD').textContent = '4.2m';
  
  // Static health indicators
  if (el('health-plc')) el('health-plc').textContent = 'OK';
  if (el('health-scada')) el('health-scada').textContent = 'Degraded';
  if (el('health-historian')) el('health-historian').textContent = 'OK';
  if (el('health-dmz')) el('health-dmz').textContent = 'Maintenance';
}

// Setup user interface
function setupUserInterface() {
  console.log('👤 Setting up user interface...');
  
  const user = dashboardAuth.getCurrentUser();
  if (user) {
    const userInfo = el('userInfo');
    const userName = el('userName');
    const userRole = el('userRole');
    
    if (userInfo && userName && userRole) {
      userName.textContent = user.displayName || user.username;
      userRole.textContent = user.role;
      userInfo.style.display = 'flex';
    }
  }
}

// Setup static event handlers
function setupEventHandlers() {
  console.log('🎛️ Setting up event handlers...');
  
  // Filter handlers (no auto-update)
  const applyBtn = el('applyFilters');
  if (applyBtn) {
    applyBtn.addEventListener('click', () => {
      console.log('🔍 Filters applied (static mode)');
    });
  }
  
  // Alert action handlers
  const ackBtn = el('ackSelected');
  const suppressBtn = el('suppressSelected');
  const exportBtn = el('exportAlerts');
  
  if (ackBtn) {
    ackBtn.addEventListener('click', () => {
      console.log('✅ Alerts acknowledged (static mode)');
    });
  }
  
  if (suppressBtn) {
    suppressBtn.addEventListener('click', () => {
      console.log('🔇 Alerts suppressed (static mode)');
    });
  }
  
  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      console.log('📥 Alerts exported (static mode)');
    });
  }
}

// Main initialization - NO INTERVALS OR TIMERS
function initDashboard() {
  console.log('🚀 Initializing STABLE Dashboard...');
  
  try {
    // Setup user interface first
    setupUserInterface();
    
    // Initialize static components
    initTopology();
    initRiskChart();
    initAttackChart();
    renderAlerts();
    setStaticValues();
    setupEventHandlers();
    
    console.log('✅ Dashboard initialized successfully (STABLE MODE)');
    console.log('📊 All components are static - no automatic updates');
    
  } catch (error) {
    console.error('❌ Dashboard initialization failed:', error);
  }
}

// Boot sequence - SINGLE EXECUTION
window.addEventListener('DOMContentLoaded', () => {
  console.log('🎯 DOM loaded - starting stable dashboard...');
  
  // Small delay to ensure all resources are loaded
  setTimeout(() => {
    initDashboard();
  }, 500);
});

// Export for debugging
window.StableDashboard = {
  initDashboard,
  staticData: staticTopologyData,
  version: 'STABLE-1.0'
};

console.log('📦 Stable Dashboard Script Loaded - No Auto Updates');