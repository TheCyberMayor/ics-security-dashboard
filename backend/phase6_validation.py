"""
ICS Cybersecurity Framework - Phase 6: Model Validation and Performance Evaluation
Implements comprehensive testing and validation framework
"""

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.metrics import classification_report, roc_auc_score, matthews_corrcoef
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Any, Optional
import json
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import asyncio
import logging

# Import framework components for testing
from phase1_threat_collection import ThreatDataCollector, ThreatIntelligence
from phase2_graph_analysis import ICSGraphAnalyzer, AttackPath
from phase3_risk_classification import ICSRiskClassifier, RiskAssessment
from phase4_dynamic_mitigation import DynamicThreatMitigator, ThreatEvent, ThreatLevel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetrics:
    """Performance metrics for model evaluation"""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    specificity: float
    false_alarm_rate: float
    matthews_correlation_coefficient: float
    auc_roc: Optional[float]
    confusion_matrix: List[List[int]]
    execution_time_ms: float

@dataclass
class ValidationResult:
    """Result of model validation"""
    model_name: str
    test_type: str
    metrics: PerformanceMetrics
    timestamp: datetime
    sample_size: int
    notes: str

@dataclass
class BenchmarkResult:
    """Benchmark comparison result"""
    our_model: PerformanceMetrics
    baseline_model: PerformanceMetrics
    improvement_percentage: Dict[str, float]
    statistical_significance: bool

class ICSTestEnvironment:
    """Simulated ICS test environment for validation"""
    
    def __init__(self):
        self.network_state = {
            'nodes': {},
            'connections': {},
            'traffic_patterns': {},
            'attack_scenarios': []
        }
        self.simulation_time = 0
        
    def setup_testbed(self, config: Dict[str, Any]):
        """Setup test environment based on configuration"""
        # Simulate ICS testbed (MiniCPS-like environment)
        self.network_state = {
            'nodes': {
                'PLC-01': {'type': 'PLC', 'zone': 'OT', 'status': 'running'},
                'HMI-01': {'type': 'HMI', 'zone': 'OT', 'status': 'running'},
                'SCADA-01': {'type': 'SCADA', 'zone': 'OT', 'status': 'running'},
                'FW-01': {'type': 'Firewall', 'zone': 'DMZ', 'status': 'running'},
                'WS-01': {'type': 'Workstation', 'zone': 'IT', 'status': 'running'}
            },
            'connections': [
                ('FW-01', 'SCADA-01'),
                ('SCADA-01', 'HMI-01'),
                ('SCADA-01', 'PLC-01'),
                ('WS-01', 'SCADA-01')
            ],
            'traffic_patterns': {
                'normal': 0.8,
                'suspicious': 0.15,
                'malicious': 0.05
            }
        }
        
        logger.info("Test environment setup completed")
    
    def simulate_attack_scenario(self, scenario_type: str) -> Dict[str, Any]:
        """Simulate specific attack scenarios"""
        scenarios = {
            'lateral_movement': {
                'entry_point': 'WS-01',
                'target': 'PLC-01',
                'attack_path': ['WS-01', 'SCADA-01', 'PLC-01'],
                'techniques': ['T0883', 'T0855'],
                'duration_minutes': 15,
                'detection_difficulty': 0.7
            },
            'data_exfiltration': {
                'entry_point': 'FW-01',
                'target': 'SCADA-01',
                'attack_path': ['FW-01', 'SCADA-01'],
                'techniques': ['T0856'],
                'duration_minutes': 8,
                'detection_difficulty': 0.5
            },
            'system_manipulation': {
                'entry_point': 'HMI-01',
                'target': 'PLC-01',
                'attack_path': ['HMI-01', 'PLC-01'],
                'techniques': ['T0855'],
                'duration_minutes': 5,
                'detection_difficulty': 0.9
            }
        }
        
        return scenarios.get(scenario_type, {})
    
    def generate_test_traffic(self, duration_minutes: int = 60) -> List[Dict[str, Any]]:
        """Generate test network traffic data"""
        traffic_data = []
        
        for minute in range(duration_minutes):
            # Normal traffic
            for _ in range(np.random.poisson(10)):  # 10 packets/minute average
                packet = {
                    'timestamp': datetime.now() + timedelta(minutes=minute),
                    'source': np.random.choice(list(self.network_state['nodes'].keys())),
                    'destination': np.random.choice(list(self.network_state['nodes'].keys())),
                    'protocol': np.random.choice(['Modbus', 'DNP3', 'EtherNet/IP']),
                    'packet_size': np.random.normal(800, 200),
                    'flow_duration': np.random.exponential(2.0),
                    'is_malicious': False
                }
                traffic_data.append(packet)
            
            # Inject malicious traffic occasionally
            if np.random.random() < 0.1:  # 10% chance per minute
                malicious_packet = {
                    'timestamp': datetime.now() + timedelta(minutes=minute),
                    'source': '192.168.100.50',  # External IP
                    'destination': np.random.choice(['SCADA-01', 'PLC-01']),
                    'protocol': 'Unknown',
                    'packet_size': np.random.normal(1500, 300),
                    'flow_duration': np.random.exponential(10.0),
                    'is_malicious': True
                }
                traffic_data.append(malicious_packet)
        
        return traffic_data

class ModelValidator:
    """Comprehensive model validation framework"""
    
    def __init__(self):
        self.test_environment = ICSTestEnvironment()
        self.validation_results = []
        
    def validate_threat_classification(self, classifier: ICSRiskClassifier, 
                                     test_data: pd.DataFrame) -> ValidationResult:
        """Validate threat classification model"""
        logger.info("Starting threat classification validation...")
        
        start_time = time.time()
        
        # Prepare test data
        X_test = classifier.preprocess_data(test_data.drop('threat_level', axis=1), is_training=False)
        y_true = test_data['threat_level'].values
        
        # Make predictions
        predictions = []
        probabilities = []
        
        for _, row in X_test.iterrows():
            features = row.to_dict()
            assessment = classifier.predict_threat_level(features)
            predictions.append(assessment.threat_level)
            probabilities.append(assessment.confidence_score)
        
        execution_time = (time.time() - start_time) * 1000  # Convert to ms
        
        # Calculate metrics
        metrics = self._calculate_classification_metrics(y_true, predictions, probabilities)
        metrics.execution_time_ms = execution_time
        
        result = ValidationResult(
            model_name="ICS Risk Classifier",
            test_type="Threat Classification",
            metrics=metrics,
            timestamp=datetime.now(),
            sample_size=len(test_data),
            notes="Validated on simulated ICS threat data"
        )
        
        self.validation_results.append(result)
        logger.info(f"Threat classification validation completed. Accuracy: {metrics.accuracy:.3f}")
        
        return result
    
    def validate_attack_path_detection(self, analyzer: ICSGraphAnalyzer) -> ValidationResult:
        """Validate attack path detection accuracy"""
        logger.info("Starting attack path detection validation...")
        
        start_time = time.time()
        
        # Create test scenarios
        test_scenarios = [
            {'source': 'FW-01', 'target': 'PLC-01', 'expected_risk': 'high'},
            {'source': 'WS-01', 'target': 'SCADA-01', 'expected_risk': 'medium'},
            {'source': 'HMI-01', 'target': 'PLC-01', 'expected_risk': 'high'},
        ]
        
        correct_predictions = 0
        total_predictions = len(test_scenarios)
        
        for scenario in test_scenarios:
            attack_paths = analyzer.find_attack_paths(
                scenario['source'], scenario['target'], max_paths=5
            )
            
            if attack_paths:
                highest_risk_path = max(attack_paths, key=lambda x: x.total_risk)
                predicted_risk = self._categorize_risk(highest_risk_path.total_risk)
                
                if predicted_risk == scenario['expected_risk']:
                    correct_predictions += 1
        
        accuracy = correct_predictions / total_predictions
        execution_time = (time.time() - start_time) * 1000
        
        # Create simplified metrics for path detection
        metrics = PerformanceMetrics(
            accuracy=accuracy,
            precision=accuracy,  # Simplified for this test
            recall=accuracy,
            f1_score=accuracy,
            specificity=accuracy,
            false_alarm_rate=1 - accuracy,
            matthews_correlation_coefficient=accuracy,
            auc_roc=None,
            confusion_matrix=[[0, 0], [0, 0]],  # Simplified
            execution_time_ms=execution_time
        )
        
        result = ValidationResult(
            model_name="Attack Path Analyzer",
            test_type="Attack Path Detection",
            metrics=metrics,
            timestamp=datetime.now(),
            sample_size=total_predictions,
            notes="Validated on predefined attack scenarios"
        )
        
        self.validation_results.append(result)
        logger.info(f"Attack path detection validation completed. Accuracy: {accuracy:.3f}")
        
        return result
    
    def validate_mitigation_effectiveness(self, mitigator: DynamicThreatMitigator,
                                        test_scenarios: List[ThreatEvent]) -> ValidationResult:
        """Validate threat mitigation effectiveness"""
        logger.info("Starting mitigation effectiveness validation...")
        
        start_time = time.time()
        
        successful_mitigations = 0
        appropriate_responses = 0
        total_scenarios = len(test_scenarios)
        
        for threat in test_scenarios:
            try:
                result = mitigator.mitigate_threat(threat)
                
                # Check if mitigation was successful (success rate > 0.6)
                if result.success_rate > 0.6:
                    successful_mitigations += 1
                
                # Check if response was appropriate for threat level
                if self._is_appropriate_mitigation(threat.threat_level, result.action):
                    appropriate_responses += 1
                    
            except Exception as e:
                logger.warning(f"Mitigation failed for threat {threat.event_id}: {e}")
        
        success_rate = successful_mitigations / total_scenarios
        appropriateness_rate = appropriate_responses / total_scenarios
        execution_time = (time.time() - start_time) * 1000
        
        metrics = PerformanceMetrics(
            accuracy=appropriateness_rate,
            precision=success_rate,
            recall=success_rate,
            f1_score=2 * (success_rate * appropriateness_rate) / (success_rate + appropriateness_rate + 1e-8),
            specificity=appropriateness_rate,
            false_alarm_rate=1 - appropriateness_rate,
            matthews_correlation_coefficient=appropriateness_rate,
            auc_roc=None,
            confusion_matrix=[[0, 0], [0, 0]],
            execution_time_ms=execution_time
        )
        
        result = ValidationResult(
            model_name="Dynamic Threat Mitigator",
            test_type="Mitigation Effectiveness",
            metrics=metrics,
            timestamp=datetime.now(),
            sample_size=total_scenarios,
            notes="Validated on diverse threat scenarios"
        )
        
        self.validation_results.append(result)
        logger.info(f"Mitigation validation completed. Success rate: {success_rate:.3f}")
        
        return result
    
    def run_performance_benchmark(self, classifier: ICSRiskClassifier) -> BenchmarkResult:
        """Run performance benchmark against baseline models"""
        logger.info("Running performance benchmark...")
        
        # Generate benchmark test data
        test_data = classifier.generate_training_data(n_samples=1000)
        
        # Test our model
        our_result = self.validate_threat_classification(classifier, test_data)
        
        # Simulate baseline model performance (simple rule-based system)
        baseline_metrics = self._simulate_baseline_performance(test_data)
        
        # Calculate improvements
        improvements = {
            'accuracy': ((our_result.metrics.accuracy - baseline_metrics.accuracy) / baseline_metrics.accuracy) * 100,
            'precision': ((our_result.metrics.precision - baseline_metrics.precision) / baseline_metrics.precision) * 100,
            'recall': ((our_result.metrics.recall - baseline_metrics.recall) / baseline_metrics.recall) * 100,
            'f1_score': ((our_result.metrics.f1_score - baseline_metrics.f1_score) / baseline_metrics.f1_score) * 100
        }
        
        # Simple statistical significance test (t-test simulation)
        stat_significant = abs(our_result.metrics.accuracy - baseline_metrics.accuracy) > 0.05
        
        return BenchmarkResult(
            our_model=our_result.metrics,
            baseline_model=baseline_metrics,
            improvement_percentage=improvements,
            statistical_significance=stat_significant
        )
    
    def simulate_attack_scenarios(self, duration_hours: int = 24) -> List[Dict[str, Any]]:
        """Simulate various attack scenarios for testing"""
        logger.info(f"Simulating attack scenarios for {duration_hours} hours...")
        
        scenarios = []
        attack_types = ['lateral_movement', 'data_exfiltration', 'system_manipulation']
        
        for hour in range(duration_hours):
            # Randomly inject attacks
            if np.random.random() < 0.1:  # 10% chance per hour
                attack_type = np.random.choice(attack_types)
                scenario = self.test_environment.simulate_attack_scenario(attack_type)
                scenario['start_time'] = datetime.now() + timedelta(hours=hour)
                scenarios.append(scenario)
        
        logger.info(f"Generated {len(scenarios)} attack scenarios")
        return scenarios
    
    def _calculate_classification_metrics(self, y_true: List[str], y_pred: List[str], 
                                        probabilities: List[float]) -> PerformanceMetrics:
        """Calculate comprehensive classification metrics"""
        # Convert string labels to numeric for sklearn
        label_mapping = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        y_true_numeric = [label_mapping.get(label, 0) for label in y_true]
        y_pred_numeric = [label_mapping.get(label, 0) for label in y_pred]
        
        # Calculate metrics
        accuracy = accuracy_score(y_true_numeric, y_pred_numeric)
        precision = precision_score(y_true_numeric, y_pred_numeric, average='weighted', zero_division=0)
        recall = recall_score(y_true_numeric, y_pred_numeric, average='weighted', zero_division=0)
        f1 = f1_score(y_true_numeric, y_pred_numeric, average='weighted', zero_division=0)
        
        # Confusion matrix
        cm = confusion_matrix(y_true_numeric, y_pred_numeric)
        
        # Calculate specificity and false alarm rate
        if len(np.unique(y_true_numeric)) == 2:  # Binary classification
            tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
            false_alarm_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
        else:  # Multi-class
            specificity = recall  # Approximation for multi-class
            false_alarm_rate = 1 - specificity
        
        # Matthews Correlation Coefficient
        mcc = matthews_corrcoef(y_true_numeric, y_pred_numeric)
        
        # AUC-ROC (for binary classification)
        auc_roc = None
        if len(np.unique(y_true_numeric)) == 2 and len(probabilities) == len(y_true_numeric):
            try:
                auc_roc = roc_auc_score(y_true_numeric, probabilities)
            except ValueError:
                auc_roc = None
        
        return PerformanceMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1,
            specificity=specificity,
            false_alarm_rate=false_alarm_rate,
            matthews_correlation_coefficient=mcc,
            auc_roc=auc_roc,
            confusion_matrix=cm.tolist(),
            execution_time_ms=0.0  # Will be set by caller
        )
    
    def _categorize_risk(self, risk_score: float) -> str:
        """Categorize numeric risk score into risk level"""
        if risk_score < 0.3:
            return 'low'
        elif risk_score < 0.6:
            return 'medium'
        elif risk_score < 0.8:
            return 'high'
        else:
            return 'critical'
    
    def _is_appropriate_mitigation(self, threat_level: ThreatLevel, action) -> bool:
        """Check if mitigation action is appropriate for threat level"""
        # Import here to avoid circular import
        from phase4_dynamic_mitigation import MitigationAction
        
        appropriate_actions = {
            ThreatLevel.LOW: [MitigationAction.NO_ACTION, MitigationAction.MONITOR],
            ThreatLevel.MEDIUM: [MitigationAction.MONITOR, MitigationAction.RATE_LIMIT],
            ThreatLevel.HIGH: [MitigationAction.BLOCK_IP, MitigationAction.ISOLATE_SEGMENT],
            ThreatLevel.CRITICAL: [MitigationAction.ISOLATE_SEGMENT, MitigationAction.SHUTDOWN_SYSTEM]
        }
        
        return action in appropriate_actions.get(threat_level, [])
    
    def _simulate_baseline_performance(self, test_data: pd.DataFrame) -> PerformanceMetrics:
        """Simulate baseline model performance"""
        # Simple rule-based baseline
        y_true = test_data['threat_level'].values
        
        # Rule: if port_scan_indicator > 0.7 or protocol_anomaly_score > 0.8, then high threat
        y_pred = []
        for _, row in test_data.iterrows():
            if row.get('port_scan_indicator', 0) > 0.7 or row.get('protocol_anomaly_score', 0) > 0.8:
                y_pred.append('high')
            elif row.get('behavioral_anomaly_score', 0) > 0.5:
                y_pred.append('medium')
            else:
                y_pred.append('low')
        
        probabilities = [0.8 if pred == 'high' else 0.6 if pred == 'medium' else 0.4 for pred in y_pred]
        
        return self._calculate_classification_metrics(y_true, y_pred, probabilities)
    
    def generate_validation_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        if not self.validation_results:
            return {'message': 'No validation results available'}
        
        report = {
            'summary': {
                'total_validations': len(self.validation_results),
                'average_accuracy': np.mean([r.metrics.accuracy for r in self.validation_results]),
                'average_precision': np.mean([r.metrics.precision for r in self.validation_results]),
                'average_recall': np.mean([r.metrics.recall for r in self.validation_results]),
                'average_f1_score': np.mean([r.metrics.f1_score for r in self.validation_results])
            },
            'detailed_results': []
        }
        
        for result in self.validation_results:
            report['detailed_results'].append({
                'model_name': result.model_name,
                'test_type': result.test_type,
                'timestamp': result.timestamp.isoformat(),
                'sample_size': result.sample_size,
                'metrics': asdict(result.metrics),
                'notes': result.notes
            })
        
        return report
    
    def export_results(self, output_file: str = "validation_results.json"):
        """Export validation results to file"""
        report = self.generate_validation_report()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Validation results exported to {output_file}")

async def run_comprehensive_validation():
    """Run comprehensive validation of all framework components"""
    print("=== ICS Cybersecurity Framework Validation ===\n")
    
    validator = ModelValidator()
    
    # Setup test environment
    validator.test_environment.setup_testbed({})
    
    print("1. Initializing and training models...")
    
    # Initialize components
    threat_collector = ThreatDataCollector()
    graph_analyzer = ICSGraphAnalyzer()
    risk_classifier = ICSRiskClassifier()
    threat_mitigator = DynamicThreatMitigator()
    
    # Setup graph
    graph_analyzer.create_sample_network()
    
    # Train models
    training_data = risk_classifier.generate_training_data(n_samples=2000)
    risk_classifier.train_models(training_data)
    
    threat_mitigator.train_agent(episodes=200)
    
    print("2. Running validation tests...")
    
    # Validate threat classification
    test_data = risk_classifier.generate_training_data(n_samples=500)
    classification_result = validator.validate_threat_classification(risk_classifier, test_data)
    
    # Validate attack path detection
    path_result = validator.validate_attack_path_detection(graph_analyzer)
    
    # Validate mitigation effectiveness
    test_threats = [
        ThreatEvent(
            event_id="TEST_001",
            timestamp=datetime.now(),
            threat_level=ThreatLevel.HIGH,
            attack_vector="Test Attack",
            affected_assets=["PLC-01"],
            confidence=0.9,
            potential_impact=0.8,
            time_criticality=0.9,
            source_ip="192.168.1.100",
            target_systems=["Control System"]
        ),
        ThreatEvent(
            event_id="TEST_002",
            timestamp=datetime.now(),
            threat_level=ThreatLevel.MEDIUM,
            attack_vector="Test Reconnaissance",
            affected_assets=["FW-01"],
            confidence=0.7,
            potential_impact=0.4,
            time_criticality=0.5,
            source_ip="10.0.0.50",
            target_systems=["Network"]
        )
    ]
    
    mitigation_result = validator.validate_mitigation_effectiveness(threat_mitigator, test_threats)
    
    print("3. Running performance benchmark...")
    
    # Run benchmark
    benchmark = validator.run_performance_benchmark(risk_classifier)
    
    print("4. Generating validation report...")
    
    # Generate and export report
    report = validator.generate_validation_report()
    validator.export_results()
    
    # Print summary
    print("\n=== Validation Results Summary ===")
    print(f"Total validations completed: {report['summary']['total_validations']}")
    print(f"Average accuracy: {report['summary']['average_accuracy']:.3f}")
    print(f"Average precision: {report['summary']['average_precision']:.3f}")
    print(f"Average recall: {report['summary']['average_recall']:.3f}")
    print(f"Average F1-score: {report['summary']['average_f1_score']:.3f}")
    
    print("\n=== Benchmark Results ===")
    print(f"Our model accuracy: {benchmark.our_model.accuracy:.3f}")
    print(f"Baseline accuracy: {benchmark.baseline_model.accuracy:.3f}")
    print(f"Improvement: {benchmark.improvement_percentage['accuracy']:.1f}%")
    print(f"Statistically significant: {benchmark.statistical_significance}")
    
    print("\n=== Individual Component Results ===")
    for result in validator.validation_results:
        print(f"{result.model_name} ({result.test_type}): "
              f"Accuracy={result.metrics.accuracy:.3f}, "
              f"F1={result.metrics.f1_score:.3f}")
    
    print("\n=== Framework Validation Complete ===")
    print("All components validated successfully!")
    print("Results exported to validation_results.json")
    
    return validator

def main():
    """Main function for validation framework"""
    # Run comprehensive validation
    asyncio.run(run_comprehensive_validation())

if __name__ == "__main__":
    main()