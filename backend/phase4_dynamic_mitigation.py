"""
ICS Cybersecurity Framework - Phase 4: Dynamic Threat Mitigation
Implements reinforcement learning for automated threat response
"""

import numpy as np
import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import gymnasium as gym
from gymnasium import spaces
import pickle

class ThreatLevel(Enum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3

class MitigationAction(Enum):
    NO_ACTION = 0
    MONITOR = 1
    RATE_LIMIT = 2
    BLOCK_IP = 3
    ISOLATE_SEGMENT = 4
    SHUTDOWN_SYSTEM = 5
    UPDATE_RULES = 6
    USER_LOCKDOWN = 7

@dataclass
class ThreatEvent:
    """Represents a cybersecurity threat event"""
    event_id: str
    timestamp: datetime
    threat_level: ThreatLevel
    attack_vector: str
    affected_assets: List[str]
    confidence: float
    potential_impact: float
    time_criticality: float
    source_ip: str
    target_systems: List[str]

@dataclass
class MitigationResult:
    """Result of a mitigation action"""
    action: MitigationAction
    success_rate: float
    cost: float
    time_to_execute: float
    side_effects: List[str]
    effectiveness_score: float

class ICSEnvironment(gym.Env):
    """Custom Gym environment for ICS threat mitigation"""
    
    def __init__(self):
        super().__init__()
        
        # Define action space (mitigation actions)
        self.action_space = spaces.Discrete(len(MitigationAction))
        
        # Define observation space
        # [threat_level, confidence, impact, time_criticality, system_health, network_load]
        self.observation_space = spaces.Box(
            low=np.array([0, 0, 0, 0, 0, 0]),
            high=np.array([1, 1, 1, 1, 1, 1]),
            dtype=np.float32
        )
        
        # Initialize environment state
        self.reset()
        
        # Mitigation effectiveness matrix
        self.mitigation_effectiveness = {
            (ThreatLevel.LOW, MitigationAction.NO_ACTION): 0.8,
            (ThreatLevel.LOW, MitigationAction.MONITOR): 0.9,
            (ThreatLevel.MEDIUM, MitigationAction.MONITOR): 0.7,
            (ThreatLevel.MEDIUM, MitigationAction.RATE_LIMIT): 0.8,
            (ThreatLevel.HIGH, MitigationAction.BLOCK_IP): 0.8,
            (ThreatLevel.HIGH, MitigationAction.ISOLATE_SEGMENT): 0.9,
            (ThreatLevel.CRITICAL, MitigationAction.ISOLATE_SEGMENT): 0.9,
            (ThreatLevel.CRITICAL, MitigationAction.SHUTDOWN_SYSTEM): 0.95,
        }
        
        # Action costs (operational impact)
        self.action_costs = {
            MitigationAction.NO_ACTION: 0.0,
            MitigationAction.MONITOR: 0.1,
            MitigationAction.RATE_LIMIT: 0.2,
            MitigationAction.BLOCK_IP: 0.3,
            MitigationAction.ISOLATE_SEGMENT: 0.6,
            MitigationAction.SHUTDOWN_SYSTEM: 0.9,
            MitigationAction.UPDATE_RULES: 0.2,
            MitigationAction.USER_LOCKDOWN: 0.4,
        }
    
    def reset(self, seed=None, options=None):
        """Reset environment to initial state"""
        super().reset(seed=seed)
        
        # Generate random threat scenario
        self.current_threat = self._generate_threat()
        self.system_health = 1.0
        self.network_load = np.random.uniform(0.2, 0.8)
        self.time_step = 0
        self.max_steps = 20
        
        return self._get_observation(), {}
    
    def step(self, action):
        """Execute action and return new state"""
        mitigation_action = MitigationAction(action)
        
        # Calculate reward
        reward = self._calculate_reward(mitigation_action)
        
        # Apply action effects
        self._apply_action_effects(mitigation_action)
        
        # Update threat status
        self._update_threat_status(mitigation_action)
        
        # Update system state
        self.time_step += 1
        
        # Check if episode is done
        done = (
            self.time_step >= self.max_steps or 
            self.current_threat.threat_level == ThreatLevel.LOW or
            self.system_health <= 0.1
        )
        
        truncated = self.time_step >= self.max_steps
        
        return self._get_observation(), reward, done, truncated, {}
    
    def _generate_threat(self) -> ThreatEvent:
        """Generate a random threat event"""
        threat_levels = list(ThreatLevel)
        attack_vectors = [
            "Network Reconnaissance", "Protocol Exploitation", 
            "Credential Theft", "Lateral Movement", "Data Exfiltration",
            "System Manipulation", "Denial of Service"
        ]
        
        return ThreatEvent(
            event_id=f"THREAT_{np.random.randint(1000, 9999)}",
            timestamp=datetime.now(),
            threat_level=np.random.choice(threat_levels),
            attack_vector=np.random.choice(attack_vectors),
            affected_assets=[f"Asset_{i}" for i in range(np.random.randint(1, 4))],
            confidence=np.random.uniform(0.6, 1.0),
            potential_impact=np.random.uniform(0.3, 1.0),
            time_criticality=np.random.uniform(0.4, 1.0),
            source_ip=f"192.168.{np.random.randint(1,10)}.{np.random.randint(1,254)}",
            target_systems=[f"System_{i}" for i in range(np.random.randint(1, 3))]
        )
    
    def _get_observation(self):
        """Get current environment observation"""
        return np.array([
            self.current_threat.threat_level.value / 3.0,  # Normalize to 0-1
            self.current_threat.confidence,
            self.current_threat.potential_impact,
            self.current_threat.time_criticality,
            self.system_health,
            self.network_load
        ], dtype=np.float32)
    
    def _calculate_reward(self, action: MitigationAction) -> float:
        """Calculate reward for taking an action"""
        threat_level = self.current_threat.threat_level
        
        # Base effectiveness
        effectiveness = self.mitigation_effectiveness.get(
            (threat_level, action), 0.5
        )
        
        # Action cost
        cost = self.action_costs[action]
        
        # Time penalty for delayed response
        time_penalty = self.current_threat.time_criticality * 0.1
        
        # Reward components
        effectiveness_reward = effectiveness * 10.0
        cost_penalty = cost * 5.0
        impact_prevention = self.current_threat.potential_impact * effectiveness * 8.0
        
        # Total reward
        reward = effectiveness_reward + impact_prevention - cost_penalty - time_penalty
        
        # Bonus for appropriate response level
        if self._is_appropriate_response(threat_level, action):
            reward += 2.0
        
        # Penalty for over/under response
        if self._is_overreaction(threat_level, action):
            reward -= 3.0
        elif self._is_underreaction(threat_level, action):
            reward -= 4.0
        
        return reward
    
    def _is_appropriate_response(self, threat_level: ThreatLevel, action: MitigationAction) -> bool:
        """Check if action is appropriate for threat level"""
        appropriate_actions = {
            ThreatLevel.LOW: [MitigationAction.NO_ACTION, MitigationAction.MONITOR],
            ThreatLevel.MEDIUM: [MitigationAction.MONITOR, MitigationAction.RATE_LIMIT, MitigationAction.UPDATE_RULES],
            ThreatLevel.HIGH: [MitigationAction.BLOCK_IP, MitigationAction.ISOLATE_SEGMENT, MitigationAction.USER_LOCKDOWN],
            ThreatLevel.CRITICAL: [MitigationAction.ISOLATE_SEGMENT, MitigationAction.SHUTDOWN_SYSTEM]
        }
        
        return action in appropriate_actions.get(threat_level, [])
    
    def _is_overreaction(self, threat_level: ThreatLevel, action: MitigationAction) -> bool:
        """Check if action is an overreaction"""
        overreactions = {
            ThreatLevel.LOW: [MitigationAction.SHUTDOWN_SYSTEM, MitigationAction.ISOLATE_SEGMENT],
            ThreatLevel.MEDIUM: [MitigationAction.SHUTDOWN_SYSTEM]
        }
        
        return action in overreactions.get(threat_level, [])
    
    def _is_underreaction(self, threat_level: ThreatLevel, action: MitigationAction) -> bool:
        """Check if action is an underreaction"""
        underreactions = {
            ThreatLevel.HIGH: [MitigationAction.NO_ACTION, MitigationAction.MONITOR],
            ThreatLevel.CRITICAL: [MitigationAction.NO_ACTION, MitigationAction.MONITOR, MitigationAction.RATE_LIMIT]
        }
        
        return action in underreactions.get(threat_level, [])
    
    def _apply_action_effects(self, action: MitigationAction):
        """Apply the effects of the chosen action"""
        # Reduce system health based on action cost
        cost = self.action_costs[action]
        self.system_health -= cost * 0.1
        
        # Update network load
        if action in [MitigationAction.RATE_LIMIT, MitigationAction.BLOCK_IP]:
            self.network_load *= 0.8  # Reduce load
        elif action == MitigationAction.SHUTDOWN_SYSTEM:
            self.network_load *= 0.3  # Significantly reduce load
        
        # Clamp values
        self.system_health = max(0.0, min(1.0, self.system_health))
        self.network_load = max(0.0, min(1.0, self.network_load))
    
    def _update_threat_status(self, action: MitigationAction):
        """Update threat level based on mitigation action"""
        effectiveness = self.mitigation_effectiveness.get(
            (self.current_threat.threat_level, action), 0.5
        )
        
        # Reduce threat level based on effectiveness
        if np.random.random() < effectiveness:
            current_level = self.current_threat.threat_level.value
            new_level = max(0, current_level - 1)
            self.current_threat.threat_level = ThreatLevel(new_level)
        
        # Reduce confidence and impact over time
        self.current_threat.confidence *= 0.95
        self.current_threat.potential_impact *= 0.9

class QLearningAgent:
    """Q-Learning agent for threat mitigation"""
    
    def __init__(self, state_size: int, action_size: int, learning_rate: float = 0.1,
                 discount_factor: float = 0.95, epsilon: float = 1.0, epsilon_decay: float = 0.995):
        self.q_table = np.zeros((state_size, action_size))
        self.learning_rate = learning_rate
        self.discount_factor = discount_factor
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = 0.01
        
    def get_action(self, state: int) -> int:
        """Choose action using epsilon-greedy policy"""
        if np.random.random() <= self.epsilon:
            return np.random.randint(0, self.q_table.shape[1])
        return np.argmax(self.q_table[state])
    
    def update_q_table(self, state: int, action: int, reward: float, next_state: int):
        """Update Q-table using Q-learning update rule"""
        current_q = self.q_table[state, action]
        max_next_q = np.max(self.q_table[next_state])
        
        new_q = current_q + self.learning_rate * (
            reward + self.discount_factor * max_next_q - current_q
        )
        
        self.q_table[state, action] = new_q
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

class DynamicThreatMitigator:
    """Main class for dynamic threat mitigation system"""
    
    def __init__(self):
        self.environment = ICSEnvironment()
        self.agent = None
        self.mitigation_history = []
        self.performance_metrics = {
            'total_threats_handled': 0,
            'successful_mitigations': 0,
            'false_positives': 0,
            'response_times': [],
            'system_availability': 1.0
        }
    
    def discretize_state(self, observation: np.ndarray, bins: int = 10) -> int:
        """Convert continuous observation to discrete state"""
        # Simple discretization - in practice, use more sophisticated methods
        discrete_obs = np.digitize(observation, 
                                 bins=np.linspace(0, 1, bins+1)[1:-1])
        
        # Convert to single state index
        state = 0
        for i, val in enumerate(discrete_obs):
            state += val * (bins ** i)
        
        return state % 1000  # Limit state space size
    
    def train_agent(self, episodes: int = 1000):
        """Train the RL agent"""
        print(f"Training agent for {episodes} episodes...")
        
        # Initialize agent
        state_size = 1000  # Discretized state space
        action_size = len(MitigationAction)
        self.agent = QLearningAgent(state_size, action_size)
        
        episode_rewards = []
        
        for episode in range(episodes):
            observation, _ = self.environment.reset()
            state = self.discretize_state(observation)
            total_reward = 0
            
            done = False
            while not done:
                # Choose action
                action = self.agent.get_action(state)
                
                # Take action
                next_observation, reward, done, truncated, _ = self.environment.step(action)
                next_state = self.discretize_state(next_observation)
                
                # Update Q-table
                self.agent.update_q_table(state, action, reward, next_state)
                
                total_reward += reward
                state = next_state
                
                if truncated:
                    done = True
            
            episode_rewards.append(total_reward)
            
            # Print progress
            if (episode + 1) % 100 == 0:
                avg_reward = np.mean(episode_rewards[-100:])
                print(f"Episode {episode + 1}/{episodes}, "
                      f"Average Reward: {avg_reward:.2f}, "
                      f"Epsilon: {self.agent.epsilon:.3f}")
        
        print("Training completed!")
        return episode_rewards
    
    def mitigate_threat(self, threat_event: ThreatEvent) -> MitigationResult:
        """Mitigate a single threat using trained agent"""
        if self.agent is None:
            raise ValueError("Agent must be trained first")
        
        start_time = datetime.now()
        
        # Convert threat to observation
        observation = np.array([
            threat_event.threat_level.value / 3.0,
            threat_event.confidence,
            threat_event.potential_impact,
            threat_event.time_criticality,
            1.0,  # system_health
            0.5   # network_load
        ], dtype=np.float32)
        
        state = self.discretize_state(observation)
        
        # Get recommended action
        action_idx = self.agent.get_action(state)
        action = MitigationAction(action_idx)
        
        # Calculate execution time
        execution_time = (datetime.now() - start_time).total_seconds()
        
        # Simulate mitigation result
        effectiveness = self.environment.mitigation_effectiveness.get(
            (threat_event.threat_level, action), 0.5
        )
        
        success_rate = effectiveness + np.random.normal(0, 0.1)
        success_rate = max(0.0, min(1.0, success_rate))
        
        result = MitigationResult(
            action=action,
            success_rate=success_rate,
            cost=self.environment.action_costs[action],
            time_to_execute=execution_time,
            side_effects=self._get_side_effects(action),
            effectiveness_score=effectiveness
        )
        
        # Record mitigation
        self.mitigation_history.append({
            'timestamp': datetime.now(),
            'threat': asdict(threat_event),
            'action': action.name,
            'result': asdict(result)
        })
        
        # Update performance metrics
        self._update_performance_metrics(threat_event, result)
        
        return result
    
    def _get_side_effects(self, action: MitigationAction) -> List[str]:
        """Get potential side effects of mitigation action"""
        side_effects_map = {
            MitigationAction.NO_ACTION: [],
            MitigationAction.MONITOR: ["Increased logging overhead"],
            MitigationAction.RATE_LIMIT: ["Potential legitimate traffic impact"],
            MitigationAction.BLOCK_IP: ["Risk of blocking legitimate users"],
            MitigationAction.ISOLATE_SEGMENT: ["Network connectivity loss", "Operational disruption"],
            MitigationAction.SHUTDOWN_SYSTEM: ["Complete service interruption", "Production loss"],
            MitigationAction.UPDATE_RULES: ["Brief connectivity interruption"],
            MitigationAction.USER_LOCKDOWN: ["User productivity impact", "Help desk load increase"]
        }
        
        return side_effects_map.get(action, [])
    
    def _update_performance_metrics(self, threat: ThreatEvent, result: MitigationResult):
        """Update system performance metrics"""
        self.performance_metrics['total_threats_handled'] += 1
        
        if result.success_rate > 0.7:
            self.performance_metrics['successful_mitigations'] += 1
        
        self.performance_metrics['response_times'].append(result.time_to_execute)
        
        # Update system availability based on action cost
        availability_impact = result.cost * 0.01
        self.performance_metrics['system_availability'] *= (1 - availability_impact)
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance report"""
        if self.performance_metrics['total_threats_handled'] == 0:
            return {"message": "No threats handled yet"}
        
        success_rate = (
            self.performance_metrics['successful_mitigations'] / 
            self.performance_metrics['total_threats_handled']
        )
        
        avg_response_time = np.mean(self.performance_metrics['response_times'])
        
        return {
            'total_threats_handled': self.performance_metrics['total_threats_handled'],
            'success_rate': success_rate,
            'average_response_time_seconds': avg_response_time,
            'system_availability': self.performance_metrics['system_availability'],
            'total_mitigations': len(self.mitigation_history),
            'action_distribution': self._get_action_distribution()
        }
    
    def _get_action_distribution(self) -> Dict[str, int]:
        """Get distribution of mitigation actions taken"""
        distribution = {}
        for record in self.mitigation_history:
            action = record['action']
            distribution[action] = distribution.get(action, 0) + 1
        return distribution
    
    def save_model(self, filepath: str = "mitigation_model.pkl"):
        """Save trained model"""
        model_data = {
            'q_table': self.agent.q_table,
            'agent_params': {
                'learning_rate': self.agent.learning_rate,
                'discount_factor': self.agent.discount_factor,
                'epsilon': self.agent.epsilon,
                'epsilon_decay': self.agent.epsilon_decay
            },
            'performance_metrics': self.performance_metrics,
            'mitigation_history': self.mitigation_history
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str = "mitigation_model.pkl"):
        """Load trained model"""
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        # Recreate agent
        state_size, action_size = model_data['q_table'].shape
        self.agent = QLearningAgent(state_size, action_size)
        self.agent.q_table = model_data['q_table']
        
        # Restore agent parameters
        params = model_data['agent_params']
        self.agent.learning_rate = params['learning_rate']
        self.agent.discount_factor = params['discount_factor']
        self.agent.epsilon = params['epsilon']
        self.agent.epsilon_decay = params['epsilon_decay']
        
        # Restore metrics and history
        self.performance_metrics = model_data['performance_metrics']
        self.mitigation_history = model_data['mitigation_history']
        
        print(f"Model loaded from {filepath}")

def main():
    """Demonstrate dynamic threat mitigation system"""
    print("=== Dynamic Threat Mitigation System ===\n")
    
    # Initialize mitigator
    mitigator = DynamicThreatMitigator()
    
    # Train the agent
    print("Training reinforcement learning agent...")
    rewards = mitigator.train_agent(episodes=500)
    
    print(f"Training completed. Final average reward: {np.mean(rewards[-100:]):.2f}")
    
    # Test mitigation on sample threats
    print("\n=== Testing Threat Mitigation ===")
    
    test_threats = [
        ThreatEvent(
            event_id="THREAT_001",
            timestamp=datetime.now(),
            threat_level=ThreatLevel.HIGH,
            attack_vector="Lateral Movement",
            affected_assets=["PLC-01", "HMI-01"],
            confidence=0.9,
            potential_impact=0.8,
            time_criticality=0.9,
            source_ip="192.168.1.100",
            target_systems=["Control System"]
        ),
        ThreatEvent(
            event_id="THREAT_002",
            timestamp=datetime.now(),
            threat_level=ThreatLevel.MEDIUM,
            attack_vector="Network Reconnaissance",
            affected_assets=["FW-01"],
            confidence=0.7,
            potential_impact=0.4,
            time_criticality=0.5,
            source_ip="10.0.0.50",
            target_systems=["Network Infrastructure"]
        ),
        ThreatEvent(
            event_id="THREAT_003",
            timestamp=datetime.now(),
            threat_level=ThreatLevel.CRITICAL,
            attack_vector="System Manipulation",
            affected_assets=["SCADA-01", "PLC-01", "PLC-02"],
            confidence=0.95,
            potential_impact=1.0,
            time_criticality=1.0,
            source_ip="172.16.0.200",
            target_systems=["Production Control"]
        )
    ]
    
    for threat in test_threats:
        print(f"\nThreat: {threat.event_id} ({threat.threat_level.name})")
        print(f"  Attack Vector: {threat.attack_vector}")
        print(f"  Confidence: {threat.confidence:.2f}")
        print(f"  Potential Impact: {threat.potential_impact:.2f}")
        
        result = mitigator.mitigate_threat(threat)
        
        print(f"  Recommended Action: {result.action.name}")
        print(f"  Success Rate: {result.success_rate:.2f}")
        print(f"  Execution Time: {result.time_to_execute:.3f}s")
        print(f"  Side Effects: {', '.join(result.side_effects) if result.side_effects else 'None'}")
    
    # Performance report
    print("\n=== Performance Report ===")
    report = mitigator.get_performance_report()
    for key, value in report.items():
        if isinstance(value, float):
            print(f"{key}: {value:.3f}")
        else:
            print(f"{key}: {value}")
    
    # Save trained model
    mitigator.save_model()
    
    print("\n=== Dynamic Threat Mitigation System Ready ===")
    print("System trained and ready for automated threat response.")

if __name__ == "__main__":
    main()