"""
ICS Cybersecurity Framework - Main Integration Script
Orchestrates all phases of the comprehensive cybersecurity framework
"""

import asyncio
import logging
import argparse
import sys
from pathlib import Path
from datetime import datetime
import json

# Framework phase imports
from phase1_threat_collection import ThreatDataCollector
from phase2_graph_analysis import ICSGraphAnalyzer
from phase3_risk_classification import ICSRiskClassifier
from phase4_dynamic_mitigation import DynamicThreatMitigator
from phase6_validation import ModelValidator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ics_framework.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ICSCybersecurityFramework:
    """Main orchestrator for the ICS Cybersecurity Framework"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.components = {}
        self.is_initialized = False
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directories
        self.output_dir = Path("output") / self.session_id
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Framework session started: {self.session_id}")
    
    def _load_config(self, config_path: str) -> dict:
        """Load framework configuration"""
        default_config = {
            "phases": {
                "threat_collection": True,
                "graph_analysis": True,
                "risk_classification": True,
                "dynamic_mitigation": True,
                "dashboard_api": False,  # Requires FastAPI
                "validation": True
            },
            "training": {
                "threat_samples": 5000,
                "mitigation_episodes": 500,
                "validation_samples": 1000
            },
            "output": {
                "export_data": True,
                "generate_reports": True,
                "save_models": True
            },
            "api": {
                "host": "localhost",
                "port": 8000,
                "enable_websocket": True
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                return {**default_config, **user_config}
        except FileNotFoundError:
            logger.info(f"Config file {config_path} not found, using defaults")
            return default_config
    
    async def initialize_framework(self):
        """Initialize all framework components"""
        logger.info("=== Initializing ICS Cybersecurity Framework ===")
        
        try:
            # Phase 1: Threat Collection
            if self.config["phases"]["threat_collection"]:
                logger.info("Phase 1: Initializing threat data collection...")
                self.components['threat_collector'] = ThreatDataCollector()
                logger.info("✓ Threat collection initialized")
            
            # Phase 2: Graph Analysis
            if self.config["phases"]["graph_analysis"]:
                logger.info("Phase 2: Initializing graph analysis...")
                self.components['graph_analyzer'] = ICSGraphAnalyzer()
                self.components['graph_analyzer'].create_sample_network()
                logger.info("✓ Graph analysis initialized with sample network")
            
            # Phase 3: Risk Classification
            if self.config["phases"]["risk_classification"]:
                logger.info("Phase 3: Initializing risk classification...")
                self.components['risk_classifier'] = ICSRiskClassifier()
                
                # Train models
                logger.info("Training ML models for risk classification...")
                training_data = self.components['risk_classifier'].generate_training_data(
                    n_samples=self.config["training"]["threat_samples"]
                )
                self.components['risk_classifier'].train_models(training_data)
                logger.info("✓ Risk classification models trained")
            
            # Phase 4: Dynamic Mitigation
            if self.config["phases"]["dynamic_mitigation"]:
                logger.info("Phase 4: Initializing dynamic threat mitigation...")
                self.components['threat_mitigator'] = DynamicThreatMitigator()
                
                # Train RL agent
                logger.info("Training reinforcement learning agent...")
                self.components['threat_mitigator'].train_agent(
                    episodes=self.config["training"]["mitigation_episodes"]
                )
                logger.info("✓ Dynamic mitigation system trained")
            
            # Phase 6: Validation
            if self.config["phases"]["validation"]:
                logger.info("Phase 6: Initializing validation framework...")
                self.components['validator'] = ModelValidator()
                logger.info("✓ Validation framework initialized")
            
            self.is_initialized = True
            logger.info("=== Framework Initialization Complete ===\n")
            
        except Exception as e:
            logger.error(f"Framework initialization failed: {e}")
            raise
    
    async def run_threat_assessment(self) -> dict:
        """Run comprehensive threat assessment"""
        if not self.is_initialized:
            await self.initialize_framework()
        
        logger.info("=== Running Threat Assessment ===")
        results = {}
        
        try:
            # Collect threat data
            if 'threat_collector' in self.components:
                logger.info("Collecting threat intelligence...")
                threat_data = await self.components['threat_collector'].collect_all_threats()
                results['threat_data'] = {
                    'mitre_threats': len(threat_data['mitre_threats']),
                    'cve_threats': len(threat_data['cve_threats']),
                    'network_events': len(threat_data['network_events'])
                }
                
                # Export threat data
                if self.config["output"]["export_data"]:
                    self.components['threat_collector'].export_to_csv(
                        threat_data, str(self.output_dir / "threat_data")
                    )
                logger.info("✓ Threat data collected and exported")
            
            # Analyze network topology and attack paths
            if 'graph_analyzer' in self.components:
                logger.info("Analyzing network topology and attack paths...")
                analyzer = self.components['graph_analyzer']
                
                # Calculate risk scores
                critical_nodes = analyzer.identify_critical_nodes(10)
                
                # Find attack paths
                attack_paths = []
                if len(analyzer.nodes) >= 2:
                    source_nodes = [n for n in analyzer.nodes if analyzer.nodes[n].zone == 'DMZ']
                    target_nodes = [n for n in analyzer.nodes if analyzer.nodes[n].node_type == 'PLC']
                    
                    for source in source_nodes[:2]:  # Limit to 2 sources
                        for target in target_nodes[:2]:  # Limit to 2 targets
                            paths = analyzer.find_attack_paths(source, target, max_paths=3)
                            attack_paths.extend(paths)
                
                results['graph_analysis'] = {
                    'critical_nodes': len(critical_nodes),
                    'attack_paths_found': len(attack_paths),
                    'highest_risk_node': critical_nodes[0] if critical_nodes else None
                }
                
                # Export analysis results
                if self.config["output"]["export_data"]:
                    analyzer.export_analysis_results(str(self.output_dir / "graph_analysis"))
                logger.info("✓ Graph analysis completed")
            
            # Risk classification
            if 'risk_classifier' in self.components:
                logger.info("Running risk classification assessment...")
                classifier = self.components['risk_classifier']
                
                # Test classification on sample data
                test_features = {
                    'packet_size': 1200,
                    'flow_duration': 5.0,
                    'packet_count': 50,
                    'unique_ports': 5,
                    'payload_entropy': 0.8,
                    'port_scan_indicator': 0.7,
                    'protocol_anomaly_score': 0.6,
                    'behavioral_anomaly_score': 0.5,
                    'reputation_score': 0.3,
                    'protocol': 'Modbus',
                    'connection_state': 'ESTABLISHED',
                    'is_encrypted': False
                }
                
                assessment = classifier.predict_threat_level(test_features)
                results['risk_assessment'] = {
                    'threat_level': assessment.threat_level,
                    'confidence': assessment.confidence_score,
                    'risk_score': assessment.risk_score,
                    'predicted_attack_vector': assessment.predicted_attack_vector
                }
                logger.info("✓ Risk classification completed")
            
            logger.info("=== Threat Assessment Complete ===\n")
            return results
            
        except Exception as e:
            logger.error(f"Threat assessment failed: {e}")
            raise
    
    async def run_validation_suite(self) -> dict:
        """Run comprehensive validation of all components"""
        if not self.is_initialized:
            await self.initialize_framework()
        
        logger.info("=== Running Validation Suite ===")
        results = {}
        
        try:
            if 'validator' in self.components:
                validator = self.components['validator']
                
                # Setup test environment
                validator.test_environment.setup_testbed({})
                
                # Validate risk classification
                if 'risk_classifier' in self.components:
                    logger.info("Validating risk classification model...")
                    test_data = self.components['risk_classifier'].generate_training_data(
                        n_samples=self.config["training"]["validation_samples"]
                    )
                    classification_result = validator.validate_threat_classification(
                        self.components['risk_classifier'], test_data
                    )
                    results['classification_validation'] = {
                        'accuracy': classification_result.metrics.accuracy,
                        'precision': classification_result.metrics.precision,
                        'recall': classification_result.metrics.recall,
                        'f1_score': classification_result.metrics.f1_score
                    }
                
                # Validate attack path detection
                if 'graph_analyzer' in self.components:
                    logger.info("Validating attack path detection...")
                    path_result = validator.validate_attack_path_detection(
                        self.components['graph_analyzer']
                    )
                    results['path_validation'] = {
                        'accuracy': path_result.metrics.accuracy
                    }
                
                # Validate mitigation effectiveness
                if 'threat_mitigator' in self.components:
                    logger.info("Validating threat mitigation...")
                    from phase4_dynamic_mitigation import ThreatEvent, ThreatLevel
                    
                    test_threats = [
                        ThreatEvent(
                            event_id="VAL_001",
                            timestamp=datetime.now(),
                            threat_level=ThreatLevel.HIGH,
                            attack_vector="Validation Test",
                            affected_assets=["PLC-01"],
                            confidence=0.9,
                            potential_impact=0.8,
                            time_criticality=0.9,
                            source_ip="192.168.1.100",
                            target_systems=["Control System"]
                        )
                    ]
                    
                    mitigation_result = validator.validate_mitigation_effectiveness(
                        self.components['threat_mitigator'], test_threats
                    )
                    results['mitigation_validation'] = {
                        'accuracy': mitigation_result.metrics.accuracy,
                        'success_rate': mitigation_result.metrics.precision
                    }
                
                # Generate validation report
                if self.config["output"]["generate_reports"]:
                    validator.export_results(str(self.output_dir / "validation_results.json"))
                
                logger.info("✓ Validation suite completed")
            
            logger.info("=== Validation Complete ===\n")
            return results
            
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            raise
    
    async def save_models(self):
        """Save all trained models"""
        if not self.is_initialized:
            return
        
        logger.info("Saving trained models...")
        models_dir = self.output_dir / "models"
        models_dir.mkdir(exist_ok=True)
        
        try:
            # Save risk classification models
            if 'risk_classifier' in self.components and self.config["output"]["save_models"]:
                self.components['risk_classifier'].save_models(str(models_dir))
                logger.info("✓ Risk classification models saved")
            
            # Save mitigation model
            if 'threat_mitigator' in self.components and self.config["output"]["save_models"]:
                self.components['threat_mitigator'].save_model(
                    str(models_dir / "mitigation_model.pkl")
                )
                logger.info("✓ Mitigation model saved")
            
        except Exception as e:
            logger.error(f"Model saving failed: {e}")
    
    async def generate_final_report(self, assessment_results: dict, validation_results: dict):
        """Generate comprehensive final report"""
        logger.info("Generating final report...")
        
        report = {
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat(),
            'framework_version': '1.0.0',
            'configuration': self.config,
            'assessment_results': assessment_results,
            'validation_results': validation_results,
            'summary': {
                'components_initialized': len(self.components),
                'phases_completed': sum(self.config['phases'].values()),
                'status': 'success'
            },
            'recommendations': [
                "Deploy models in production environment",
                "Setup continuous monitoring and model updates",
                "Integrate with existing SIEM/SOAR systems",
                "Establish incident response procedures",
                "Schedule regular model retraining"
            ]
        }
        
        # Save report
        report_path = self.output_dir / "final_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Final report saved to: {report_path}")
        return report

async def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(description='ICS Cybersecurity Framework')
    parser.add_argument('--config', default='config.json', help='Configuration file path')
    parser.add_argument('--mode', choices=['full', 'assess', 'validate'], default='full',
                       help='Execution mode')
    parser.add_argument('--api', action='store_true', help='Start API server after processing')
    
    args = parser.parse_args()
    
    # Initialize framework
    framework = ICSCybersecurityFramework(args.config)
    
    try:
        print("🔒 ICS Cybersecurity Framework")
        print("=" * 50)
        
        assessment_results = {}
        validation_results = {}
        
        if args.mode in ['full', 'assess']:
            # Run threat assessment
            assessment_results = await framework.run_threat_assessment()
            
            print("\n📊 Assessment Results:")
            for phase, results in assessment_results.items():
                print(f"  {phase}: {results}")
        
        if args.mode in ['full', 'validate']:
            # Run validation
            validation_results = await framework.run_validation_suite()
            
            print("\n✅ Validation Results:")
            for validation, results in validation_results.items():
                print(f"  {validation}: {results}")
        
        # Save models
        await framework.save_models()
        
        # Generate final report
        final_report = await framework.generate_final_report(
            assessment_results, validation_results
        )
        
        print(f"\n🎯 Framework Execution Complete!")
        print(f"Session ID: {framework.session_id}")
        print(f"Output Directory: {framework.output_dir}")
        print(f"Components Initialized: {len(framework.components)}")
        
        # Start API server if requested
        if args.api:
            print("\n🚀 Starting API server...")
            try:
                from phase5_dashboard_api import app
                import uvicorn
                uvicorn.run(app, host="localhost", port=8000)
            except ImportError:
                print("API server requires FastAPI. Install with: pip install fastapi uvicorn")
        
        return final_report
        
    except Exception as e:
        logger.error(f"Framework execution failed: {e}")
        raise
    
    except KeyboardInterrupt:
        logger.info("Framework execution interrupted by user")
        print("\n👋 Framework execution stopped by user")

if __name__ == "__main__":
    asyncio.run(main())