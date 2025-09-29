"""
ICS Cybersecurity Framework - Phase 5: Dashboard API and Integration
Implements FastAPI backend for real-time dashboard and system integration
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any
import asyncio
import json
import uvicorn
from datetime import datetime, timedelta
import numpy as np
import logging
from contextlib import asynccontextmanager

# Import our framework components
from phase1_threat_collection import ThreatDataCollector, ThreatIntelligence, ICSEvent
from phase2_graph_analysis import ICSGraphAnalyzer, AttackPath
from phase3_risk_classification import ICSRiskClassifier, RiskAssessment
from phase4_dynamic_mitigation import DynamicThreatMitigator, ThreatEvent, ThreatLevel, MitigationResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Pydantic models for API
class ThreatEventAPI(BaseModel):
    event_id: str
    timestamp: datetime
    threat_level: str
    attack_vector: str
    affected_assets: List[str]
    confidence: float = Field(..., ge=0.0, le=1.0)
    potential_impact: float = Field(..., ge=0.0, le=1.0)
    source_ip: str
    target_systems: List[str]

class MitigationRequest(BaseModel):
    threat_id: str
    manual_override: bool = False
    preferred_action: Optional[str] = None

class NetworkNodeAPI(BaseModel):
    node_id: str
    node_type: str
    zone: str
    risk_score: float
    vulnerabilities: List[str]
    status: str = "online"

class DashboardMetrics(BaseModel):
    total_threats: int
    active_threats: int
    system_health: float
    network_load: float
    mitigation_success_rate: float
    average_response_time: float

class AlertAPI(BaseModel):
    alert_id: str
    title: str
    severity: str
    zone: str
    timestamp: datetime
    status: str = "open"
    description: str

# Global system components
system_components = {
    'threat_collector': None,
    'graph_analyzer': None,
    'risk_classifier': None,
    'threat_mitigator': None,
    'active_threats': {},
    'websocket_connections': set(),
    'system_metrics': {
        'uptime': datetime.now(),
        'total_threats_processed': 0,
        'active_mitigations': 0
    }
}

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except:
            self.disconnect(websocket)

    async def broadcast(self, message: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize system components on startup"""
    logger.info("Initializing ICS Cybersecurity Framework...")
    
    # Initialize components
    system_components['threat_collector'] = ThreatDataCollector()
    system_components['graph_analyzer'] = ICSGraphAnalyzer()
    system_components['risk_classifier'] = ICSRiskClassifier()
    system_components['threat_mitigator'] = DynamicThreatMitigator()
    
    # Setup sample network
    system_components['graph_analyzer'].create_sample_network()
    
    # Train ML models (in background)
    asyncio.create_task(initialize_ml_models())
    
    # Start background monitoring
    asyncio.create_task(background_monitoring())
    
    logger.info("System initialization completed")
    yield
    
    logger.info("Shutting down ICS Cybersecurity Framework...")

# Create FastAPI app
app = FastAPI(
    title="ICS Cybersecurity Framework API",
    description="Advanced cybersecurity framework for Industrial Control Systems",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files (dashboard)
app.mount("/static", StaticFiles(directory="../dashboard"), name="static")

async def initialize_ml_models():
    """Initialize ML models in background"""
    try:
        logger.info("Training ML models...")
        
        # Train risk classifier
        classifier = system_components['risk_classifier']
        training_data = classifier.generate_training_data(n_samples=2000)
        classifier.train_models(training_data)
        
        # Train threat mitigator
        mitigator = system_components['threat_mitigator']
        mitigator.train_agent(episodes=200)
        
        logger.info("ML models training completed")
        
        # Broadcast system ready status
        await manager.broadcast({
            'type': 'system_status',
            'status': 'ready',
            'message': 'ML models trained and ready'
        })
        
    except Exception as e:
        logger.error(f"Error initializing ML models: {e}")

async def background_monitoring():
    """Background task for continuous monitoring"""
    while True:
        try:
            # Collect threat data
            collector = system_components['threat_collector']
            threat_data = await collector.collect_all_threats()
            
            # Process new threats
            for threat in threat_data['mitre_threats'] + threat_data['cve_threats']:
                await process_new_threat(threat)
            
            # Update dashboard metrics
            metrics = await get_current_metrics()
            await manager.broadcast({
                'type': 'metrics_update',
                'data': metrics
            })
            
            # Wait before next collection
            await asyncio.sleep(30)  # Every 30 seconds
            
        except Exception as e:
            logger.error(f"Background monitoring error: {e}")
            await asyncio.sleep(60)  # Wait longer on error

async def process_new_threat(threat_intel: ThreatIntelligence):
    """Process a new threat intelligence item"""
    try:
        # Convert to threat event
        severity_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        
        threat_event = ThreatEvent(
            event_id=threat_intel.threat_id,
            timestamp=threat_intel.timestamp,
            threat_level=severity_mapping.get(threat_intel.severity, ThreatLevel.MEDIUM),
            attack_vector=threat_intel.mitre_technique,
            affected_assets=threat_intel.affected_systems,
            confidence=0.8,  # Default confidence
            potential_impact=0.6,  # Default impact
            time_criticality=0.7,  # Default criticality
            source_ip="unknown",
            target_systems=threat_intel.affected_systems
        )
        
        # Store active threat
        system_components['active_threats'][threat_event.event_id] = threat_event
        
        # Auto-mitigate if system is ready
        if system_components['threat_mitigator'].agent is not None:
            result = system_components['threat_mitigator'].mitigate_threat(threat_event)
            
            # Broadcast threat and mitigation
            await manager.broadcast({
                'type': 'new_threat',
                'threat': {
                    'event_id': threat_event.event_id,
                    'threat_level': threat_event.threat_level.name,
                    'attack_vector': threat_event.attack_vector,
                    'confidence': threat_event.confidence
                },
                'mitigation': {
                    'action': result.action.name,
                    'success_rate': result.success_rate,
                    'cost': result.cost
                }
            })
            
            system_components['system_metrics']['total_threats_processed'] += 1
        
    except Exception as e:
        logger.error(f"Error processing threat: {e}")

# API Routes

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main dashboard"""
    try:
        with open("../dashboard/index.html", "r") as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>Dashboard not found</h1><p>Please ensure the dashboard files are in the correct location.</p>")

@app.get("/api/health")
async def health_check():
    """API health check"""
    uptime = datetime.now() - system_components['system_metrics']['uptime']
    
    return {
        "status": "healthy",
        "uptime_seconds": uptime.total_seconds(),
        "components": {
            "threat_collector": system_components['threat_collector'] is not None,
            "graph_analyzer": system_components['graph_analyzer'] is not None,
            "risk_classifier": system_components['risk_classifier'] is not None and 
                             system_components['risk_classifier'].is_trained,
            "threat_mitigator": system_components['threat_mitigator'] is not None and
                              system_components['threat_mitigator'].agent is not None
        }
    }

@app.get("/api/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics():
    """Get current dashboard metrics"""
    return await get_current_metrics()

async def get_current_metrics() -> DashboardMetrics:
    """Calculate current system metrics"""
    active_threats = len([t for t in system_components['active_threats'].values() 
                         if t.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]])
    
    # Calculate system health based on active threats and mitigations
    threat_count = len(system_components['active_threats'])
    system_health = max(0.3, 1.0 - (threat_count * 0.1))
    
    # Simulate network load
    network_load = min(0.9, 0.3 + (active_threats * 0.1))
    
    # Get mitigation success rate
    mitigator = system_components['threat_mitigator']
    perf_report = mitigator.get_performance_report()
    
    success_rate = perf_report.get('success_rate', 0.0) if isinstance(perf_report, dict) else 0.0
    avg_response_time = perf_report.get('average_response_time_seconds', 0.0) if isinstance(perf_report, dict) else 0.0
    
    return DashboardMetrics(
        total_threats=system_components['system_metrics']['total_threats_processed'],
        active_threats=active_threats,
        system_health=system_health,
        network_load=network_load,
        mitigation_success_rate=success_rate,
        average_response_time=avg_response_time
    )

@app.get("/api/threats")
async def get_active_threats():
    """Get list of active threats"""
    threats = []
    for threat_event in system_components['active_threats'].values():
        threats.append({
            'event_id': threat_event.event_id,
            'timestamp': threat_event.timestamp.isoformat(),
            'threat_level': threat_event.threat_level.name,
            'attack_vector': threat_event.attack_vector,
            'affected_assets': threat_event.affected_assets,
            'confidence': threat_event.confidence,
            'potential_impact': threat_event.potential_impact,
            'source_ip': threat_event.source_ip
        })
    
    return {'threats': threats}

@app.post("/api/threats")
async def submit_threat(threat: ThreatEventAPI):
    """Submit a new threat for analysis"""
    try:
        # Convert API model to internal model
        threat_level_mapping = {
            'low': ThreatLevel.LOW,
            'medium': ThreatLevel.MEDIUM,
            'high': ThreatLevel.HIGH,
            'critical': ThreatLevel.CRITICAL
        }
        
        threat_event = ThreatEvent(
            event_id=threat.event_id,
            timestamp=threat.timestamp,
            threat_level=threat_level_mapping[threat.threat_level.lower()],
            attack_vector=threat.attack_vector,
            affected_assets=threat.affected_assets,
            confidence=threat.confidence,
            potential_impact=threat.potential_impact,
            time_criticality=0.8,  # Default
            source_ip=threat.source_ip,
            target_systems=threat.target_systems
        )
        
        # Process threat
        await process_new_threat_from_api(threat_event)
        
        return {'status': 'success', 'message': 'Threat submitted successfully'}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

async def process_new_threat_from_api(threat_event: ThreatEvent):
    """Process threat submitted via API"""
    # Store threat
    system_components['active_threats'][threat_event.event_id] = threat_event
    
    # Mitigate if possible
    if system_components['threat_mitigator'].agent is not None:
        result = system_components['threat_mitigator'].mitigate_threat(threat_event)
        
        # Broadcast to WebSocket clients
        await manager.broadcast({
            'type': 'threat_submitted',
            'threat': {
                'event_id': threat_event.event_id,
                'threat_level': threat_event.threat_level.name,
                'attack_vector': threat_event.attack_vector
            },
            'mitigation': {
                'action': result.action.name,
                'success_rate': result.success_rate
            }
        })

@app.post("/api/mitigate")
async def request_mitigation(request: MitigationRequest):
    """Request mitigation for a specific threat"""
    try:
        if request.threat_id not in system_components['active_threats']:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        threat_event = system_components['active_threats'][request.threat_id]
        
        # Perform mitigation
        mitigator = system_components['threat_mitigator']
        if mitigator.agent is None:
            raise HTTPException(status_code=503, detail="Mitigation system not ready")
        
        result = mitigator.mitigate_threat(threat_event)
        
        # Broadcast result
        await manager.broadcast({
            'type': 'mitigation_result',
            'threat_id': request.threat_id,
            'action': result.action.name,
            'success_rate': result.success_rate,
            'cost': result.cost
        })
        
        return {
            'status': 'success',
            'action': result.action.name,
            'success_rate': result.success_rate,
            'cost': result.cost,
            'side_effects': result.side_effects
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/network/topology")
async def get_network_topology():
    """Get network topology data"""
    analyzer = system_components['graph_analyzer']
    
    # Convert NetworkX graph to API format
    nodes = []
    edges = []
    
    for node_id, node_data in analyzer.graph.nodes(data=True):
        grs = analyzer.compute_graph_theoretic_risk_score(node_id)
        nodes.append({
            'id': node_id,
            'label': node_id,
            'type': node_data.get('node_type', 'unknown'),
            'zone': node_data.get('zone', 'unknown'),
            'risk_score': grs,
            'size': 10 + (grs * 30),
            'color': get_risk_color(grs)
        })
    
    for source, target, edge_data in analyzer.graph.edges(data=True):
        edges.append({
            'from': source,
            'to': target,
            'protocol': edge_data.get('protocol', 'unknown'),
            'encrypted': edge_data.get('encrypted', False)
        })
    
    return {
        'nodes': nodes,
        'edges': edges
    }

@app.get("/api/network/attack-paths")
async def get_attack_paths():
    """Get potential attack paths"""
    analyzer = system_components['graph_analyzer']
    
    # Find attack paths between external and critical assets
    external_nodes = [n for n, d in analyzer.graph.nodes(data=True) 
                     if d.get('zone') == 'DMZ']
    critical_nodes = [n for n, d in analyzer.graph.nodes(data=True) 
                     if d.get('node_type') == 'PLC']
    
    attack_paths = []
    
    for ext_node in external_nodes[:2]:  # Limit to 2 external nodes
        for crit_node in critical_nodes[:2]:  # Limit to 2 critical nodes
            paths = analyzer.find_attack_paths(ext_node, crit_node, max_paths=3)
            for path in paths:
                attack_paths.append({
                    'path_id': path.path_id,
                    'nodes': path.nodes,
                    'total_risk': path.total_risk,
                    'likelihood': path.likelihood,
                    'impact': path.impact,
                    'techniques': path.attack_techniques
                })
    
    return {'attack_paths': attack_paths}

@app.get("/api/analysis/risk-scores")
async def get_risk_scores():
    """Get risk scores for all nodes"""
    analyzer = system_components['graph_analyzer']
    
    risk_scores = {}
    for node_id in analyzer.nodes:
        grs = analyzer.compute_graph_theoretic_risk_score(node_id)
        risk_scores[node_id] = grs
    
    return {'risk_scores': risk_scores}

@app.get("/api/alerts")
async def get_alerts():
    """Get system alerts"""
    alerts = []
    
    # Convert active threats to alerts
    for threat_event in system_components['active_threats'].values():
        alerts.append({
            'alert_id': threat_event.event_id,
            'title': f"{threat_event.attack_vector} detected",
            'severity': threat_event.threat_level.name.lower(),
            'zone': threat_event.affected_assets[0] if threat_event.affected_assets else "unknown",
            'timestamp': threat_event.timestamp.isoformat(),
            'status': 'open',
            'description': f"Threat level: {threat_event.threat_level.name}, Confidence: {threat_event.confidence:.2f}"
        })
    
    return {'alerts': alerts}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle different message types
            if message.get('type') == 'ping':
                await websocket.send_text(json.dumps({'type': 'pong'}))
            elif message.get('type') == 'subscribe':
                # Client subscribed to updates
                current_metrics = await get_current_metrics()
                await websocket.send_text(json.dumps({
                    'type': 'initial_data',
                    'metrics': current_metrics.dict()
                }))
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)

def get_risk_color(risk_score: float) -> str:
    """Get color based on risk score"""
    if risk_score < 0.3:
        return '#22c55e'  # green
    elif risk_score < 0.6:
        return '#eab308'  # yellow
    elif risk_score < 0.8:
        return '#f59e0b'  # orange
    else:
        return '#ef4444'  # red

@app.post("/api/system/collect-threats")
async def trigger_threat_collection(background_tasks: BackgroundTasks):
    """Manually trigger threat data collection"""
    background_tasks.add_task(collect_and_process_threats)
    return {'status': 'success', 'message': 'Threat collection triggered'}

async def collect_and_process_threats():
    """Background task for threat collection"""
    try:
        collector = system_components['threat_collector']
        threat_data = await collector.collect_all_threats()
        
        # Process each threat
        for threat in threat_data['mitre_threats'] + threat_data['cve_threats']:
            await process_new_threat(threat)
        
        logger.info(f"Processed {len(threat_data['mitre_threats']) + len(threat_data['cve_threats'])} threats")
        
    except Exception as e:
        logger.error(f"Error in threat collection: {e}")

# Additional utility endpoints

@app.get("/api/system/status")
async def get_system_status():
    """Get detailed system status"""
    uptime = datetime.now() - system_components['system_metrics']['uptime']
    
    return {
        'uptime_hours': uptime.total_seconds() / 3600,
        'total_threats_processed': system_components['system_metrics']['total_threats_processed'],
        'active_threats_count': len(system_components['active_threats']),
        'websocket_connections': len(manager.active_connections),
        'components_status': {
            'threat_collector': 'ready' if system_components['threat_collector'] else 'not_initialized',
            'graph_analyzer': 'ready' if system_components['graph_analyzer'] else 'not_initialized',
            'risk_classifier': 'trained' if (system_components['risk_classifier'] and 
                                           system_components['risk_classifier'].is_trained) else 'training',
            'threat_mitigator': 'trained' if (system_components['threat_mitigator'] and 
                                            system_components['threat_mitigator'].agent) else 'training'
        }
    }

if __name__ == "__main__":
    print("Starting ICS Cybersecurity Framework API...")
    print("Dashboard will be available at: http://localhost:8000")
    print("API documentation at: http://localhost:8000/docs")
    
    uvicorn.run(
        "phase5_dashboard_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )