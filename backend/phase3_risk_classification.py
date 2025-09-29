"""
ICS Cybersecurity Framework - Phase 3: Risk Scoring and Threat Classification
Implements ML-based risk assessment and dynamic threat classification
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
import joblib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import warnings
warnings.filterwarnings('ignore')

@dataclass
class ThreatFeatures:
    """Feature vector for threat classification"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    packet_size: int
    flow_duration: float
    packet_count: int
    bytes_per_second: float
    packets_per_second: float
    unique_ports: int
    tcp_flags: int
    payload_entropy: float
    time_between_packets: float
    connection_state: str
    is_encrypted: bool
    port_scan_indicator: float
    protocol_anomaly_score: float
    behavioral_anomaly_score: float
    geographic_risk_score: float
    reputation_score: float

@dataclass
class RiskAssessment:
    """Risk assessment result"""
    asset_id: str
    timestamp: datetime
    threat_level: str  # low, medium, high, critical
    confidence_score: float
    risk_score: float
    contributing_factors: List[str]
    recommended_actions: List[str]
    predicted_attack_vector: str
    time_to_compromise: float
    business_impact: float

class ICSRiskClassifier:
    """Multi-layered ML-based risk classification for ICS environments
    
    Implements three decision engines:
    1. Device Risk Classification (GNN-like layer) - 5-class probability distribution
    2. Attack Classification (Packet-level) - Binary classification with confidence
    3. Feature extraction and risk scoring
    """
    
    def __init__(self):
        self.models = {
            'device_risk': None,        # 5-class device risk classifier
            'attack_detector': None,    # Binary attack classifier
            'anomaly_detector': None    # Isolation Forest for anomalies
        }
        self.scalers = {}
        self.label_encoders = {}
        self.feature_columns = []
        self.risk_classes = ["Normal", "Low", "Medium", "High", "Critical"]
        self.is_trained = False
        
    def classify_device_risk(self, device_features: Dict[str, Any]) -> Dict[str, Any]:
        """Device Risk Classification (GNN-like layer)
        
        Assesses PLC/device threat levels using network context and device features.
        Returns probability distribution over 5 classes: [Normal, Low, Medium, High, Critical]
        
        Args:
            device_features: Dictionary containing device information:
                - device_id: str
                - device_type: str (PLC, HMI, SCADA, etc.)
                - firmware_vulnerabilities: List[str]
                - communication_patterns: Dict (degree_centrality, connections, etc.)
                - operational_criticality: str (HIGH/MEDIUM/LOW)
                - network_context: Dict (neighboring devices, protocols, etc.)
        
        Returns:
            Dictionary with risk classification results
        """
        if not self.is_trained or 'device_risk' not in self.models:
            # Return default classification if model not trained
            return {
                "device_id": device_features.get("device_id", "unknown"),
                "risk_probabilities": [0.6, 0.2, 0.1, 0.08, 0.02],  # Default: mostly normal
                "predicted_class": "Normal",
                "confidence": 0.6,
                "risk_factors": [],
                "explanation": "Model not trained - using default classification"
            }
        
        # Extract features for classification
        feature_vector = self._extract_device_features(device_features)
        
        # Get probability distribution from model
        if hasattr(self.models['device_risk'], 'predict_proba'):
            probabilities = self.models['device_risk'].predict_proba([feature_vector])[0]
        else:
            # Fallback for models without predict_proba
            prediction = self.models['device_risk'].predict([feature_vector])[0]
            probabilities = [0.0] * len(self.risk_classes)
            predicted_idx = self.risk_classes.index(prediction)
            probabilities[predicted_idx] = 0.8
            # Distribute remaining probability
            remaining = 0.2 / (len(self.risk_classes) - 1)
            for i in range(len(probabilities)):
                if i != predicted_idx:
                    probabilities[i] = remaining
        
        # Get predicted class and confidence
        predicted_idx = np.argmax(probabilities)
        predicted_class = self.risk_classes[predicted_idx]
        confidence = probabilities[predicted_idx]
        
        # Identify contributing risk factors
        risk_factors = self._identify_risk_factors(device_features, feature_vector)
        
        # Generate explanation
        explanation = self._generate_device_risk_explanation(
            device_features, predicted_class, probabilities, risk_factors
        )
        
        return {
            "device_id": device_features.get("device_id", "unknown"),
            "device_type": device_features.get("device_type", "unknown"),
            "risk_probabilities": probabilities.tolist(),
            "risk_classes": self.risk_classes,
            "predicted_class": predicted_class,
            "confidence": float(confidence),
            "risk_factors": risk_factors,
            "explanation": explanation,
            "timestamp": datetime.now().isoformat()
        }
    
    def classify_network_attack(self, packet_features: Dict[str, Any]) -> Dict[str, Any]:
        """Attack Classification (Packet-Level)
        
        Binary classifier for flagging malicious network packets in real-time.
        Analyzes protocol anomalies, temporal patterns, and payload signatures.
        
        Args:
            packet_features: Dictionary containing packet information:
                - protocol: str (MODBUS, DNP3, etc.)
                - function_code: str/int
                - payload_size: int
                - temporal_pattern: Dict (burst detection, timing analysis)
                - payload_signatures: List[str] (known exploit patterns)
                - source_info: Dict (IP, reputation, geolocation)
        
        Returns:
            Dictionary with attack classification results
        """
        if not self.is_trained or 'attack_detector' not in self.models:
            return {
                "classification": "Normal",
                "confidence": 0.5,
                "attack_probability": 0.1,
                "explanation": "Model not trained - using default classification",
                "detected_patterns": []
            }
        
        # Extract features for attack detection
        feature_vector = self._extract_packet_features(packet_features)
        
        # Get binary classification (0=Normal, 1=Attack)
        if hasattr(self.models['attack_detector'], 'predict_proba'):
            probabilities = self.models['attack_detector'].predict_proba([feature_vector])[0]
            attack_probability = probabilities[1] if len(probabilities) > 1 else 0.0
        else:
            prediction = self.models['attack_detector'].predict([feature_vector])[0]
            attack_probability = 0.9 if prediction == 1 else 0.1
        
        # Classify based on threshold
        is_attack = attack_probability > 0.5
        classification = "Attack" if is_attack else "Normal"
        confidence = attack_probability if is_attack else (1 - attack_probability)
        
        # Detect specific attack patterns
        detected_patterns = self._detect_attack_patterns(packet_features)
        
        # Generate explanation
        explanation = self._generate_attack_explanation(
            packet_features, classification, confidence, detected_patterns
        )
        
        return {
            "classification": classification,
            "confidence": float(confidence),
            "attack_probability": float(attack_probability),
            "detected_patterns": detected_patterns,
            "explanation": explanation,
            "timestamp": datetime.now().isoformat()
        }
    
    def _extract_device_features(self, device_features: Dict[str, Any]) -> List[float]:
        """Extract numerical features for device risk classification"""
        features = []
        
        # Device type encoding
        device_type_map = {'PLC': 1.0, 'HMI': 0.8, 'SCADA': 0.9, 'RTU': 0.7, 'Firewall': 0.3}
        features.append(device_type_map.get(device_features.get('device_type', ''), 0.5))
        
        # Vulnerability count
        vulns = device_features.get('firmware_vulnerabilities', [])
        features.append(min(len(vulns) / 5.0, 1.0))  # Normalize to 0-1
        
        # Criticality
        criticality_map = {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3}
        features.append(criticality_map.get(device_features.get('operational_criticality', 'MEDIUM'), 0.6))
        
        # Communication patterns
        comm_patterns = device_features.get('communication_patterns', {})
        features.append(comm_patterns.get('degree_centrality', 0.0))
        features.append(min(comm_patterns.get('connection_count', 0) / 10.0, 1.0))
        
        # Network context
        network_ctx = device_features.get('network_context', {})
        features.append(len(network_ctx.get('protocols', [])) / 5.0)  # Protocol diversity
        features.append(network_ctx.get('zone_risk', 0.5))  # Network zone risk
        
        return features
    
    def _extract_packet_features(self, packet_features: Dict[str, Any]) -> List[float]:
        """Extract numerical features for attack classification"""
        features = []
        
        # Protocol risk mapping
        protocol_risk = {
            'MODBUS': 0.8, 'DNP3': 0.7, 'PROFINET': 0.6,
            'EtherNet/IP': 0.5, 'HTTP': 0.4, 'HTTPS': 0.2
        }
        features.append(protocol_risk.get(packet_features.get('protocol', ''), 0.5))
        
        # Function code anomaly (for industrial protocols)
        func_code = packet_features.get('function_code', 0)
        if isinstance(func_code, str):
            func_code = hash(func_code) % 256  # Convert to numeric
        features.append(func_code / 256.0)  # Normalize
        
        # Payload characteristics
        features.append(min(packet_features.get('payload_size', 0) / 1500.0, 1.0))
        
        # Temporal patterns
        temporal = packet_features.get('temporal_pattern', {})
        features.append(temporal.get('burst_indicator', 0.0))
        features.append(temporal.get('timing_anomaly', 0.0))
        
        # Source reputation
        source_info = packet_features.get('source_info', {})
        features.append(1.0 - source_info.get('reputation_score', 0.5))  # Invert reputation
        
        # Payload entropy (if available)
        features.append(packet_features.get('payload_entropy', 0.5))
        
        return features
    
    def _identify_risk_factors(self, device_features: Dict[str, Any], 
                              feature_vector: List[float]) -> List[str]:
        """Identify contributing risk factors for device classification"""
        risk_factors = []
        
        # Check vulnerabilities
        vulns = device_features.get('firmware_vulnerabilities', [])
        if len(vulns) > 2:
            risk_factors.append(f"Multiple vulnerabilities detected ({len(vulns)})")
        
        # Check criticality
        if device_features.get('operational_criticality') == 'HIGH':
            risk_factors.append("High operational criticality")
        
        # Check communication patterns
        comm = device_features.get('communication_patterns', {})
        if comm.get('degree_centrality', 0) > 0.7:
            risk_factors.append("High network connectivity")
        
        # Check network context
        network = device_features.get('network_context', {})
        if len(network.get('protocols', [])) > 3:
            risk_factors.append("Multiple protocol exposure")
        
        return risk_factors
    
    def _detect_attack_patterns(self, packet_features: Dict[str, Any]) -> List[str]:
        """Detect specific attack patterns in packet data"""
        patterns = []
        
        protocol = packet_features.get('protocol', '')
        func_code = packet_features.get('function_code', '')
        
        # MODBUS attack patterns
        if protocol == 'MODBUS':
            if func_code in ['Write_Single_Coil', 'Write_Multiple_Coils']:
                patterns.append("MODBUS unauthorized write command")
            if packet_features.get('payload_size', 0) > 1000:
                patterns.append("MODBUS oversized payload")
        
        # Temporal attack patterns
        temporal = packet_features.get('temporal_pattern', {})
        if temporal.get('burst_indicator', 0) > 0.8:
            patterns.append("DoS burst pattern detected")
        if temporal.get('timing_anomaly', 0) > 0.7:
            patterns.append("Slow reconnaissance pattern")
        
        # Payload signature patterns
        signatures = packet_features.get('payload_signatures', [])
        for sig in signatures:
            if 'exploit' in sig.lower():
                patterns.append(f"Known exploit signature: {sig}")
        
        return patterns
    
    def _generate_device_risk_explanation(self, device_features: Dict[str, Any], 
                                        predicted_class: str, probabilities: np.ndarray,
                                        risk_factors: List[str]) -> str:
        """Generate human-readable explanation for device risk classification"""
        device_id = device_features.get('device_id', 'Unknown')
        confidence = probabilities[self.risk_classes.index(predicted_class)]
        
        explanation = f"Device {device_id} classified as '{predicted_class}' "
        explanation += f"with {confidence:.2f} confidence. "
        
        if risk_factors:
            explanation += f"Key risk factors: {', '.join(risk_factors[:3])}. "
        
        # Add probability distribution context
        top_2_indices = np.argsort(probabilities)[-2:][::-1]
        if len(top_2_indices) > 1:
            second_class = self.risk_classes[top_2_indices[1]]
            second_prob = probabilities[top_2_indices[1]]
            explanation += f"Secondary risk: {second_class} ({second_prob:.2f}). "
        
        return explanation
    
    def _generate_attack_explanation(self, packet_features: Dict[str, Any], 
                                   classification: str, confidence: float,
                                   patterns: List[str]) -> str:
        """Generate human-readable explanation for attack classification"""
        explanation = f"Packet classified as '{classification}' with {confidence:.2f} confidence. "
        
        if patterns:
            explanation += f"Detected patterns: {', '.join(patterns[:2])}. "
        
        protocol = packet_features.get('protocol', 'Unknown')
        explanation += f"Protocol: {protocol}. "
        
        return explanation
    
    def generate_training_data(self, n_samples: int = 10000) -> pd.DataFrame:
        """Generate synthetic training data for ICS threat classification"""
        np.random.seed(42)
        
        data = []
        protocols = ['Modbus', 'DNP3', 'EtherNet/IP', 'PROFINET', 'OPC', 'HTTP', 'HTTPS', 'SSH']
        connection_states = ['ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT', 'CLOSED', 'LISTEN']
        threat_levels = ['low', 'medium', 'high', 'critical']
        
        for i in range(n_samples):
            # Generate base features
            protocol = np.random.choice(protocols)
            
            # Normal vs malicious traffic patterns
            is_malicious = np.random.random() < 0.3  # 30% malicious
            
            if is_malicious:
                # Malicious traffic characteristics
                packet_size = np.random.normal(1200, 400)
                flow_duration = np.random.exponential(2.0)
                packet_count = np.random.poisson(50)
                unique_ports = np.random.poisson(8)
                payload_entropy = np.random.normal(0.8, 0.1)
                port_scan_indicator = np.random.uniform(0.6, 1.0)
                protocol_anomaly_score = np.random.uniform(0.5, 1.0)
                behavioral_anomaly_score = np.random.uniform(0.4, 1.0)
                reputation_score = np.random.uniform(0.0, 0.4)
                
                # Determine threat level based on characteristics for device risk
                device_risk_level = np.random.choice(self.risk_classes, p=[0.1, 0.2, 0.3, 0.3, 0.1])
                
                # For attack classification (binary)
                is_attack = 1
                
                risk_factors = [
                    payload_entropy > 0.7,
                    port_scan_indicator > 0.7,
                    protocol_anomaly_score > 0.6,
                    unique_ports > 5,
                    reputation_score < 0.3
                ]
                
                risk_count = sum(risk_factors)
                if risk_count >= 4:
                    threat_level = 'critical'
                elif risk_count >= 3:
                    threat_level = 'high'
                elif risk_count >= 2:
                    threat_level = 'medium'
                else:
                    threat_level = 'low'
                    
            else:
                # Normal traffic characteristics
                packet_size = np.random.normal(800, 200)
                flow_duration = np.random.exponential(0.5)
                packet_count = np.random.poisson(20)
                unique_ports = np.random.poisson(2)
                payload_entropy = np.random.normal(0.4, 0.1)
                port_scan_indicator = np.random.uniform(0.0, 0.3)
                protocol_anomaly_score = np.random.uniform(0.0, 0.3)
                behavioral_anomaly_score = np.random.uniform(0.0, 0.3)
                reputation_score = np.random.uniform(0.6, 1.0)
                threat_level = 'low'
            
            # Derived features
            bytes_per_second = packet_size * packet_count / max(flow_duration, 0.1)
            packets_per_second = packet_count / max(flow_duration, 0.1)
            time_between_packets = flow_duration / max(packet_count, 1)
            
            features = ThreatFeatures(
                timestamp=datetime.now() - timedelta(hours=np.random.randint(0, 168)),
                source_ip=f"192.168.{np.random.randint(1,10)}.{np.random.randint(1,254)}",
                dest_ip=f"10.0.{np.random.randint(1,5)}.{np.random.randint(1,254)}",
                protocol=protocol,
                packet_size=max(int(packet_size), 64),
                flow_duration=max(flow_duration, 0.01),
                packet_count=max(packet_count, 1),
                bytes_per_second=bytes_per_second,
                packets_per_second=packets_per_second,
                unique_ports=max(unique_ports, 1),
                tcp_flags=np.random.randint(0, 256),
                payload_entropy=np.clip(payload_entropy, 0.0, 1.0),
                time_between_packets=time_between_packets,
                connection_state=np.random.choice(connection_states),
                is_encrypted=np.random.random() < 0.3,
                port_scan_indicator=np.clip(port_scan_indicator, 0.0, 1.0),
                protocol_anomaly_score=np.clip(protocol_anomaly_score, 0.0, 1.0),
                behavioral_anomaly_score=np.clip(behavioral_anomaly_score, 0.0, 1.0),
                geographic_risk_score=np.random.uniform(0.0, 1.0),
                reputation_score=np.clip(reputation_score, 0.0, 1.0)
            )
            
            # Convert to dict for DataFrame
            feature_dict = {
                'packet_size': features.packet_size,
                'flow_duration': features.flow_duration,
                'packet_count': features.packet_count,
                'bytes_per_second': features.bytes_per_second,
                'packets_per_second': features.packets_per_second,
                'unique_ports': features.unique_ports,
                'tcp_flags': features.tcp_flags,
                'payload_entropy': features.payload_entropy,
                'time_between_packets': features.time_between_packets,
                'is_encrypted': int(features.is_encrypted),
                'port_scan_indicator': features.port_scan_indicator,
                'protocol_anomaly_score': features.protocol_anomaly_score,
                'behavioral_anomaly_score': features.behavioral_anomaly_score,
                'geographic_risk_score': features.geographic_risk_score,
                'reputation_score': features.reputation_score,
                'protocol': features.protocol,
                'connection_state': features.connection_state,
                'threat_level': threat_level
            }
            
            data.append(feature_dict)
        
        return pd.DataFrame(data)
    
    def preprocess_data(self, df: pd.DataFrame, is_training: bool = True) -> pd.DataFrame:
        """Preprocess data for machine learning"""
        df_processed = df.copy()
        
        # Handle categorical variables
        categorical_columns = ['protocol', 'connection_state']
        
        for col in categorical_columns:
            if is_training:
                le = LabelEncoder()
                df_processed[col] = le.fit_transform(df_processed[col])
                self.label_encoders[col] = le
            else:
                if col in self.label_encoders:
                    # Handle unseen categories
                    le = self.label_encoders[col]
                    df_processed[col] = df_processed[col].map(
                        lambda x: le.transform([x])[0] if x in le.classes_ else -1
                    )
        
        # Select numerical features
        if is_training:
            self.feature_columns = [col for col in df_processed.columns 
                                  if col not in ['threat_level'] and 
                                  df_processed[col].dtype in ['int64', 'float64']]
        
        X = df_processed[self.feature_columns]
        
        # Scale features
        if is_training:
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            self.scalers['standard'] = scaler
        else:
            if 'standard' in self.scalers:
                X_scaled = self.scalers['standard'].transform(X)
            else:
                X_scaled = X.values
        
        return pd.DataFrame(X_scaled, columns=self.feature_columns)
    
    def train_models(self, df: pd.DataFrame) -> Dict[str, Dict]:
        """Train multiple ML models for threat classification"""
        print("Preprocessing training data...")
        X = self.preprocess_data(df, is_training=True)
        y = df['threat_level']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")
        
        # Model configurations
        model_configs = {
            'random_forest': {
                'model': RandomForestClassifier(random_state=42),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [10, 20, None],
                    'min_samples_split': [2, 5]
                }
            },
            'svm': {
                'model': SVC(random_state=42, probability=True),
                'params': {
                    'C': [0.1, 1, 10],
                    'kernel': ['rbf', 'linear'],
                    'gamma': ['scale', 'auto']
                }
            },
            'xgboost': {
                'model': xgb.XGBClassifier(random_state=42, eval_metric='mlogloss'),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [3, 6, 10],
                    'learning_rate': [0.01, 0.1, 0.2]
                }
            }
        }
        
        results = {}
        
        # Train each model
        for name, config in model_configs.items():
            print(f"\nTraining {name}...")
            
            # Grid search for hyperparameter tuning
            grid_search = GridSearchCV(
                config['model'], 
                config['params'], 
                cv=3, 
                scoring='accuracy',
                n_jobs=-1
            )
            
            grid_search.fit(X_train, y_train)
            
            # Best model
            best_model = grid_search.best_estimator_
            
            # Predictions
            y_pred = best_model.predict(X_test)
            y_pred_proba = best_model.predict_proba(X_test)
            
            # Metrics
            accuracy = accuracy_score(y_test, y_pred)
            classification_rep = classification_report(y_test, y_pred, output_dict=True)
            
            # Store results
            results[name] = {
                'model': best_model,
                'accuracy': accuracy,
                'classification_report': classification_rep,
                'best_params': grid_search.best_params_,
                'predictions': y_pred,
                'probabilities': y_pred_proba
            }
            
            self.models[name] = best_model
            
            print(f"  Best params: {grid_search.best_params_}")
            print(f"  Accuracy: {accuracy:.4f}")
        
        # Train anomaly detection model
        print("\nTraining anomaly detection model...")
        isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        isolation_forest.fit(X_train)
        
        anomaly_scores = isolation_forest.decision_function(X_test)
        anomaly_predictions = isolation_forest.predict(X_test)
        
        self.models['isolation_forest'] = isolation_forest
        results['isolation_forest'] = {
            'model': isolation_forest,
            'anomaly_scores': anomaly_scores,
            'predictions': anomaly_predictions
        }
        
        self.is_trained = True
        print("\nModel training completed!")
        
        return results
    
    def predict_threat_level(self, features: Dict[str, Any], 
                           model_name: str = 'random_forest') -> RiskAssessment:
        """Predict threat level for new data"""
        if not self.is_trained:
            raise ValueError("Models must be trained first")
        
        if model_name not in self.models:
            raise ValueError(f"Model {model_name} not available")
        
        # Convert features to DataFrame
        feature_df = pd.DataFrame([features])
        
        # Preprocess
        X = self.preprocess_data(feature_df, is_training=False)
        
        # Predict
        model = self.models[model_name]
        prediction = model.predict(X)[0]
        
        if hasattr(model, 'predict_proba'):
            probabilities = model.predict_proba(X)[0]
            confidence = max(probabilities)
        else:
            confidence = 0.8  # Default confidence
        
        # Calculate risk score
        risk_mapping = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0}
        risk_score = risk_mapping.get(prediction, 0.5)
        
        # Determine contributing factors
        contributing_factors = []
        if features.get('port_scan_indicator', 0) > 0.6:
            contributing_factors.append("Port scanning detected")
        if features.get('protocol_anomaly_score', 0) > 0.6:
            contributing_factors.append("Protocol anomaly")
        if features.get('payload_entropy', 0) > 0.7:
            contributing_factors.append("High payload entropy")
        if features.get('reputation_score', 1.0) < 0.3:
            contributing_factors.append("Low reputation score")
        
        # Recommended actions
        recommended_actions = []
        if prediction in ['high', 'critical']:
            recommended_actions.extend([
                "Isolate affected systems",
                "Investigate traffic patterns",
                "Update firewall rules"
            ])
        elif prediction == 'medium':
            recommended_actions.extend([
                "Monitor closely",
                "Review access logs"
            ])
        else:
            recommended_actions.append("Continue monitoring")
        
        # Predict attack vector
        attack_vector = "Unknown"
        if features.get('port_scan_indicator', 0) > 0.7:
            attack_vector = "Network reconnaissance"
        elif features.get('protocol_anomaly_score', 0) > 0.7:
            attack_vector = "Protocol exploitation"
        elif features.get('payload_entropy', 0) > 0.8:
            attack_vector = "Data exfiltration"
        
        return RiskAssessment(
            asset_id=features.get('asset_id', 'unknown'),
            timestamp=datetime.now(),
            threat_level=prediction,
            confidence_score=confidence,
            risk_score=risk_score,
            contributing_factors=contributing_factors,
            recommended_actions=recommended_actions,
            predicted_attack_vector=attack_vector,
            time_to_compromise=np.random.exponential(24.0),  # Hours
            business_impact=risk_score * np.random.uniform(0.5, 1.0)
        )
    
    def update_model_with_feedback(self, features: Dict[str, Any], 
                                 true_label: str, model_name: str = 'random_forest'):
        """Update model with new labeled data (online learning simulation)"""
        # In a real implementation, this would update the model incrementally
        # For now, we'll simulate by adding to a feedback buffer
        
        feedback_entry = {
            'features': features,
            'true_label': true_label,
            'timestamp': datetime.now(),
            'model': model_name
        }
        
        # In production, you would:
        # 1. Store feedback in a database
        # 2. Periodically retrain models with new data
        # 3. A/B test model versions
        # 4. Monitor for concept drift
        
        print(f"Feedback received for {model_name}: {true_label}")
        return feedback_entry
    
    def save_models(self, output_dir: str = "models"):
        """Save trained models and preprocessing objects"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Save models
        for name, model in self.models.items():
            joblib.dump(model, f"{output_dir}/{name}_model.pkl")
        
        # Save scalers
        for name, scaler in self.scalers.items():
            joblib.dump(scaler, f"{output_dir}/{name}_scaler.pkl")
        
        # Save label encoders
        for name, encoder in self.label_encoders.items():
            joblib.dump(encoder, f"{output_dir}/{name}_encoder.pkl")
        
        # Save feature columns
        with open(f"{output_dir}/feature_columns.json", 'w') as f:
            json.dump(self.feature_columns, f)
        
        print(f"Models saved to {output_dir}/")
    
    def load_models(self, model_dir: str = "models"):
        """Load trained models and preprocessing objects"""
        import os
        
        # Load feature columns
        with open(f"{model_dir}/feature_columns.json", 'r') as f:
            self.feature_columns = json.load(f)
        
        # Load models
        for filename in os.listdir(model_dir):
            if filename.endswith('_model.pkl'):
                model_name = filename.replace('_model.pkl', '')
                self.models[model_name] = joblib.load(f"{model_dir}/{filename}")
        
        # Load scalers
        for filename in os.listdir(model_dir):
            if filename.endswith('_scaler.pkl'):
                scaler_name = filename.replace('_scaler.pkl', '')
                self.scalers[scaler_name] = joblib.load(f"{model_dir}/{filename}")
        
        # Load encoders
        for filename in os.listdir(model_dir):
            if filename.endswith('_encoder.pkl'):
                encoder_name = filename.replace('_encoder.pkl', '')
                self.label_encoders[encoder_name] = joblib.load(f"{model_dir}/{filename}")
        
        self.is_trained = True
        print(f"Models loaded from {model_dir}/")

def main():
    """Demonstrate ICS risk classification and threat assessment"""
    print("=== ICS Risk Classification and Threat Assessment ===\n")
    
    # Initialize classifier
    classifier = ICSRiskClassifier()
    
    # Generate training data
    print("Generating synthetic training data...")
    training_data = classifier.generate_training_data(n_samples=5000)
    print(f"Generated {len(training_data)} training samples")
    print(f"Threat level distribution:")
    print(training_data['threat_level'].value_counts())
    
    # Train models
    results = classifier.train_models(training_data)
    
    # Display results
    print("\n=== Model Performance ===")
    for model_name, result in results.items():
        if 'accuracy' in result:
            print(f"\n{model_name.upper()}:")
            print(f"  Accuracy: {result['accuracy']:.4f}")
            if 'classification_report' in result:
                print("  Classification Report:")
                for class_name, metrics in result['classification_report'].items():
                    if isinstance(metrics, dict):
                        print(f"    {class_name}: precision={metrics.get('precision', 0):.3f}, "
                              f"recall={metrics.get('recall', 0):.3f}, "
                              f"f1-score={metrics.get('f1-score', 0):.3f}")
    
    # Test prediction on new data
    print("\n=== Testing Predictions ===")
    
    # Create test samples
    test_samples = [
        {
            'packet_size': 1500,
            'flow_duration': 10.0,
            'packet_count': 100,
            'unique_ports': 10,
            'payload_entropy': 0.9,
            'port_scan_indicator': 0.8,
            'protocol_anomaly_score': 0.7,
            'behavioral_anomaly_score': 0.6,
            'reputation_score': 0.2,
            'protocol': 'Modbus',
            'connection_state': 'ESTABLISHED',
            'is_encrypted': False,
            'asset_id': 'PLC-01'
        },
        {
            'packet_size': 512,
            'flow_duration': 2.0,
            'packet_count': 10,
            'unique_ports': 1,
            'payload_entropy': 0.3,
            'port_scan_indicator': 0.1,
            'protocol_anomaly_score': 0.2,
            'behavioral_anomaly_score': 0.1,
            'reputation_score': 0.9,
            'protocol': 'DNP3',
            'connection_state': 'ESTABLISHED',
            'is_encrypted': True,
            'asset_id': 'RTU-01'
        }
    ]
    
    for i, sample in enumerate(test_samples, 1):
        print(f"\nTest Sample {i} (Asset: {sample['asset_id']}):")
        
        # Test with different models
        for model_name in ['random_forest', 'xgboost']:
            if model_name in classifier.models:
                assessment = classifier.predict_threat_level(sample, model_name)
                print(f"  {model_name}: {assessment.threat_level} "
                      f"(confidence: {assessment.confidence_score:.3f}, "
                      f"risk: {assessment.risk_score:.3f})")
                print(f"    Attack Vector: {assessment.predicted_attack_vector}")
                print(f"    Contributing Factors: {', '.join(assessment.contributing_factors)}")
    
    # Save models
    classifier.save_models()
    
    print("\n=== Risk Classification System Ready ===")
    print("Models trained and saved. System ready for real-time threat assessment.")

if __name__ == "__main__":
    main()