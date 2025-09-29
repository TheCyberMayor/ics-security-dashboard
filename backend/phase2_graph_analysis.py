"""
ICS Cybersecurity Framework - Phase 2: Graph-Theoretic Representation
Implements graph modeling of ICS networks with attack path analysis
"""

import networkx as nx
import numpy as np
import json
import matplotlib.pyplot as plt
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
import random
from pathlib import Path

@dataclass
class ICSNode:
    """Represents an ICS system component"""
    node_id: str
    node_type: str  # PLC, HMI, SCADA, RTU, Firewall, Switch
    zone: str       # IT, DMZ, OT, PLC
    criticality: float  # 0.0 to 1.0
    vulnerabilities: List[str]
    risk_score: float
    manufacturer: str
    model: str
    ip_address: str
    
@dataclass 
class ICSEdge:
    """Represents communication between ICS components"""
    source: str
    target: str
    protocol: str   # Modbus, DNP3, EtherNet/IP, etc.
    connection_type: str  # data, control, management
    bandwidth: float
    latency: float
    encrypted: bool
    trust_level: float  # 0.0 to 1.0

@dataclass
class AttackPath:
    """Represents a potential attack path through the network"""
    path_id: str
    nodes: List[str]
    edges: List[Tuple[str, str]]
    attack_techniques: List[str]
    total_risk: float
    likelihood: float
    impact: float
    mitigation_cost: float

class ICSGraphAnalyzer:
    """Graph-theoretic analysis of ICS security"""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.attack_graph = nx.DiGraph()
        self.nodes: Dict[str, ICSNode] = {}
        self.edges: Dict[Tuple[str, str], ICSEdge] = {}
        
    def create_sample_network(self) -> None:
        """Create a sample ICS network topology"""
        # Define sample nodes
        sample_nodes = [
            ICSNode("FW-01", "Firewall", "DMZ", 0.9, ["CVE-2023-1001"], 0.3, "Cisco", "ASA-5506", "192.168.1.1"),
            ICSNode("SCADA-01", "SCADA", "OT", 0.95, ["CVE-2023-1002"], 0.6, "Wonderware", "InTouch", "10.0.1.10"),
            ICSNode("HMI-01", "HMI", "OT", 0.8, [], 0.2, "Siemens", "WinCC", "10.0.1.20"),
            ICSNode("PLC-01", "PLC", "PLC", 1.0, ["T0855"], 0.8, "Allen-Bradley", "ControlLogix", "10.0.2.10"),
            ICSNode("PLC-02", "PLC", "PLC", 1.0, ["T0856"], 0.7, "Siemens", "S7-1500", "10.0.2.11"),
            ICSNode("RTU-01", "RTU", "OT", 0.85, [], 0.4, "Schneider", "ION7650", "10.0.1.30"),
            ICSNode("HIST-01", "Historian", "OT", 0.7, [], 0.3, "OSIsoft", "PI Server", "10.0.1.40"),
            ICSNode("EWS-01", "Engineering Workstation", "OT", 0.6, ["T0883"], 0.5, "Dell", "Precision", "10.0.1.50")
        ]
        
        # Define sample edges
        sample_edges = [
            ICSEdge("FW-01", "SCADA-01", "TCP/IP", "data", 1000.0, 5.0, True, 0.8),
            ICSEdge("SCADA-01", "HMI-01", "Ethernet", "data", 100.0, 2.0, False, 0.9),
            ICSEdge("SCADA-01", "PLC-01", "Modbus", "control", 100.0, 10.0, False, 0.7),
            ICSEdge("SCADA-01", "PLC-02", "PROFINET", "control", 100.0, 8.0, False, 0.7),
            ICSEdge("SCADA-01", "RTU-01", "DNP3", "control", 56.0, 15.0, False, 0.6),
            ICSEdge("SCADA-01", "HIST-01", "OPC", "data", 100.0, 3.0, False, 0.8),
            ICSEdge("EWS-01", "PLC-01", "Ethernet/IP", "management", 100.0, 5.0, False, 0.5),
            ICSEdge("EWS-01", "PLC-02", "S7", "management", 100.0, 5.0, False, 0.5)
        ]
        
        # Add nodes to graph
        for node in sample_nodes:
            self.nodes[node.node_id] = node
            self.graph.add_node(node.node_id, **asdict(node))
            
        # Add edges to graph
        for edge in sample_edges:
            self.edges[(edge.source, edge.target)] = edge
            self.graph.add_edge(edge.source, edge.target, **asdict(edge))
    
    def calculate_centrality_measures(self) -> Dict[str, Dict[str, float]]:
        """Calculate various centrality measures for nodes"""
        measures = {}
        
        # Degree centrality
        degree_cent = nx.degree_centrality(self.graph)
        
        # Betweenness centrality
        betweenness_cent = nx.betweenness_centrality(self.graph)
        
        # Closeness centrality
        closeness_cent = nx.closeness_centrality(self.graph)
        
        # Eigenvector centrality
        try:
            eigenvector_cent = nx.eigenvector_centrality(self.graph, max_iter=1000)
        except nx.PowerIterationFailedConvergence:
            eigenvector_cent = {node: 0.0 for node in self.graph.nodes()}
        
        # PageRank
        pagerank = nx.pagerank(self.graph)
        
        # Combine all measures
        for node in self.graph.nodes():
            measures[node] = {
                "degree_centrality": degree_cent[node],
                "betweenness_centrality": betweenness_cent[node],
                "closeness_centrality": closeness_cent[node],
                "eigenvector_centrality": eigenvector_cent[node],
                "pagerank": pagerank[node]
            }
            
        return measures
    
    def compute_graph_theoretic_risk_score(self, node_id: str) -> float:
        """Compute enhanced Graph-Theoretic Risk Score (GRS) using NRS + ERS + PRS formula"""
        if node_id not in self.nodes:
            return 0.0
            
        # Calculate Node Risk Score (NRS)
        nrs = self._calculate_node_risk_score(node_id)
        
        # Calculate Edge Risk Score (ERS)
        ers = self._calculate_edge_risk_score(node_id)
        
        # Calculate Path Risk Score (PRS)
        prs = self._calculate_path_risk_score_for_node(node_id)
        
        # Combine using weighted GRS formula: GRS = α*NRS + β*ERS + γ*PRS
        alpha, beta, gamma = 0.4, 0.3, 0.3  # Configurable weights
        grs = alpha * nrs + beta * ers + gamma * prs
        
        return min(grs, 1.0)
    
    def _calculate_node_risk_score(self, node_id: str) -> float:
        """Calculate Node Risk Score (NRS) based on inherent vulnerabilities"""
        node = self.nodes[node_id]
        
        # Base vulnerability score from CVEs and MITRE techniques
        vuln_score = 0.0
        for vuln in node.vulnerabilities:
            if vuln.startswith('CVE-'):
                # Simulate CVSS score (in practice, fetch from NVD)
                vuln_score += random.uniform(0.4, 1.0)  # High-impact vulnerabilities
            elif vuln.startswith('T0'):
                # MITRE ATT&CK technique impact
                vuln_score += 0.6
        
        # Normalize by max expected vulnerabilities
        vuln_score = min(vuln_score / 3.0, 1.0)
        
        # Factor in criticality and existing risk score
        criticality_factor = node.criticality
        base_risk_factor = node.risk_score
        
        # Firmware/patch status (simulated)
        firmware_risk = random.uniform(0.1, 0.4) if node.node_type == 'PLC' else 0.1
        
        nrs = (vuln_score * 0.5 + criticality_factor * 0.3 + 
               base_risk_factor * 0.1 + firmware_risk * 0.1)
        
        return min(nrs, 1.0)
    
    def _calculate_edge_risk_score(self, node_id: str) -> float:
        """Calculate Edge Risk Score (ERS) for communication links"""
        total_edge_risk = 0.0
        edge_count = 0
        
        # Examine all edges connected to this node
        for neighbor in self.graph.neighbors(node_id):
            edge_data = self.graph[node_id][neighbor]
            
            # Protocol risk assessment
            protocol_risk = {
                'Modbus': 0.8,      # Unencrypted, minimal authentication
                'DNP3': 0.7,        # Better than Modbus but still vulnerable
                'PROFINET': 0.6,    # Industrial Ethernet, moderate security
                'EtherNet/IP': 0.5, # More secure industrial protocol
                'S7': 0.7,          # Siemens proprietary, known vulnerabilities
                'OPC': 0.6,         # Depends on implementation
                'TCP/IP': 0.4       # Can be secured with proper configuration
            }.get(edge_data.get('protocol', 'Unknown'), 0.5)
            
            # Encryption factor
            encryption_factor = 0.3 if edge_data.get('encrypted', False) else 1.0
            
            # Trust level (inverse relationship with risk)
            trust_factor = 1 - edge_data.get('trust_level', 0.5)
            
            # Connection type risk
            connection_risk = {
                'control': 0.9,     # Direct control = highest risk
                'data': 0.6,        # Data exfiltration/manipulation
                'management': 0.7   # Administrative access
            }.get(edge_data.get('connection_type', 'data'), 0.6)
            
            edge_risk = (protocol_risk * 0.4 + trust_factor * 0.3 + 
                        connection_risk * 0.3) * encryption_factor
            
            total_edge_risk += edge_risk
            edge_count += 1
        
        # Also check incoming edges
        for predecessor in self.graph.predecessors(node_id):
            if predecessor != node_id:  # Avoid double counting
                edge_data = self.graph[predecessor][node_id]
                protocol_risk = {
                    'Modbus': 0.8, 'DNP3': 0.7, 'PROFINET': 0.6,
                    'EtherNet/IP': 0.5, 'S7': 0.7, 'OPC': 0.6, 'TCP/IP': 0.4
                }.get(edge_data.get('protocol', 'Unknown'), 0.5)
                
                encryption_factor = 0.3 if edge_data.get('encrypted', False) else 1.0
                trust_factor = 1 - edge_data.get('trust_level', 0.5)
                connection_risk = {
                    'control': 0.9, 'data': 0.6, 'management': 0.7
                }.get(edge_data.get('connection_type', 'data'), 0.6)
                
                edge_risk = (protocol_risk * 0.4 + trust_factor * 0.3 + 
                            connection_risk * 0.3) * encryption_factor
                
                total_edge_risk += edge_risk
                edge_count += 1
        
        return total_edge_risk / max(edge_count, 1)
    
    def _calculate_path_risk_score_for_node(self, node_id: str) -> float:
        """Calculate Path Risk Score (PRS) for attack propagation routes"""
        if not hasattr(self, '_path_risk_cache'):
            self._path_risk_cache = {}
        
        if node_id in self._path_risk_cache:
            return self._path_risk_cache[node_id]
        
        max_path_risk = 0.0
        
        # Find critical nodes (high-value targets)
        critical_nodes = [n for n, data in self.graph.nodes(data=True) 
                         if data.get('criticality', 0) > 0.8]
        
        # Calculate risk of paths from/to this node to critical infrastructure
        for critical_node in critical_nodes[:5]:  # Limit for performance
            if critical_node == node_id:
                continue
                
            try:
                # Path TO critical infrastructure (attack propagation)
                if nx.has_path(self.graph, node_id, critical_node):
                    path = nx.shortest_path(self.graph, node_id, critical_node)
                    path_risk = self._calculate_attack_path_risk(path)
                    max_path_risk = max(max_path_risk, path_risk)
                
                # Path FROM potential entry points (initial compromise)
                entry_points = [n for n, data in self.graph.nodes(data=True)
                              if data.get('zone') in ['DMZ', 'IT'] or 
                              data.get('node_type') in ['Firewall', 'Engineering Workstation']]
                
                for entry_point in entry_points[:3]:
                    if (entry_point != node_id and 
                        nx.has_path(self.graph, entry_point, node_id)):
                        path = nx.shortest_path(self.graph, entry_point, node_id)
                        path_risk = self._calculate_attack_path_risk(path) * 0.8  # Slightly lower weight
                        max_path_risk = max(max_path_risk, path_risk)
                        
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
        
        self._path_risk_cache[node_id] = min(max_path_risk, 1.0)
        return self._path_risk_cache[node_id]
    
    def _calculate_attack_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for a specific attack path"""
        if len(path) < 2:
            return 0.0
        
        total_risk = 0.0
        path_length_penalty = min(len(path) * 0.1, 0.5)  # Longer paths are riskier
        
        for i in range(len(path) - 1):
            current_node = path[i]
            next_node = path[i + 1]
            
            # Node vulnerability contribution
            if current_node in self.nodes:
                node_vuln = len(self.nodes[current_node].vulnerabilities) * 0.2
                total_risk += node_vuln
            
            # Edge traversal difficulty (inverse of trust level)
            if self.graph.has_edge(current_node, next_node):
                edge_data = self.graph[current_node][next_node]
                traversal_risk = 1 - edge_data.get('trust_level', 0.5)
                total_risk += traversal_risk
        
        # Normalize and add path length penalty
        normalized_risk = (total_risk / len(path)) + path_length_penalty
        return min(normalized_risk, 1.0)
    
    def find_attack_paths(self, source: str, target: str, max_paths: int = 10) -> List[AttackPath]:
        """Find potential attack paths between source and target nodes"""
        attack_paths = []
        
        try:
            # Find all simple paths (avoiding cycles)
            simple_paths = list(nx.all_simple_paths(self.graph, source, target, cutoff=6))
            
            # Limit number of paths to analyze
            simple_paths = simple_paths[:max_paths]
            
            for i, path in enumerate(simple_paths):
                # Calculate path risk
                path_risk = self._calculate_path_risk(path)
                
                # Get attack techniques for path
                techniques = self._get_path_attack_techniques(path)
                
                # Create edges list
                edges = [(path[j], path[j+1]) for j in range(len(path)-1)]
                
                attack_path = AttackPath(
                    path_id=f"PATH_{i:03d}_{source}_{target}",
                    nodes=path,
                    edges=edges,
                    attack_techniques=techniques,
                    total_risk=path_risk["total_risk"],
                    likelihood=path_risk["likelihood"],
                    impact=path_risk["impact"],
                    mitigation_cost=path_risk["mitigation_cost"]
                )
                
                attack_paths.append(attack_path)
                
        except nx.NetworkXNoPath:
            print(f"No path found between {source} and {target}")
            
        return sorted(attack_paths, key=lambda x: x.total_risk, reverse=True)
    
    def _calculate_path_risk(self, path: List[str]) -> Dict[str, float]:
        """Calculate risk metrics for an attack path"""
        total_risk = 0.0
        likelihood = 1.0
        impact = 0.0
        mitigation_cost = 0.0
        
        for node_id in path:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                grs = self.compute_graph_theoretic_risk_score(node_id)
                
                total_risk += grs
                likelihood *= (1 - grs)  # Probability of successful compromise
                impact += node.criticality
                mitigation_cost += grs * 10000  # Arbitrary cost unit
        
        likelihood = 1 - likelihood  # Overall path success probability
        
        return {
            "total_risk": min(total_risk / len(path), 1.0),  # Average risk
            "likelihood": likelihood,
            "impact": min(impact / len(path), 1.0),  # Average impact
            "mitigation_cost": mitigation_cost
        }
    
    def _get_path_attack_techniques(self, path: List[str]) -> List[str]:
        """Get relevant MITRE ATT&CK techniques for a path"""
        techniques = set()
        
        for node_id in path:
            if node_id in self.nodes:
                node = self.nodes[node_id]
                for vuln in node.vulnerabilities:
                    if vuln.startswith("T0"):  # MITRE technique
                        techniques.add(vuln)
                    else:  # CVE - map to technique
                        techniques.add("T0883")  # Internet Accessible Device
        
        return list(techniques)
    
    def calculate_risk_likelihood(self, grs: float, k: float = 10.0, 
                                 threshold: float = 0.5) -> float:
        """Convert GRS to Risk Likelihood using sigmoid function
        
        Args:
            grs: Graph-Theoretic Risk Score (0-1)
            k: Steepness parameter (higher = more sensitive)
            threshold: Midpoint threshold (0-1)
        
        Returns:
            Risk likelihood probability (0-1)
        """
        # Sigmoid transformation: L(GRS) = 1 / (1 + e^(-k*(GRS - threshold)))
        import math
        
        try:
            likelihood = 1 / (1 + math.exp(-k * (grs - threshold)))
        except OverflowError:
            # Handle extreme values
            likelihood = 1.0 if grs > threshold else 0.0
        
        return likelihood
    
    def get_risk_classification(self, node_id: str) -> Dict[str, any]:
        """Get comprehensive risk classification for a node"""
        grs = self.compute_graph_theoretic_risk_score(node_id)
        likelihood = self.calculate_risk_likelihood(grs)
        
        # Risk level classification
        if likelihood < 0.2:
            risk_level = "Normal"
            priority = "Low"
        elif likelihood < 0.4:
            risk_level = "Low"
            priority = "Medium"
        elif likelihood < 0.6:
            risk_level = "Medium"
            priority = "Medium"
        elif likelihood < 0.8:
            risk_level = "High"
            priority = "High"
        else:
            risk_level = "Critical"
            priority = "Critical"
        
        # Get component scores
        nrs = self._calculate_node_risk_score(node_id)
        ers = self._calculate_edge_risk_score(node_id)
        prs = self._calculate_path_risk_score_for_node(node_id)
        
        return {
            "node_id": node_id,
            "grs": grs,
            "risk_likelihood": likelihood,
            "risk_level": risk_level,
            "priority": priority,
            "components": {
                "node_risk_score": nrs,
                "edge_risk_score": ers,
                "path_risk_score": prs
            },
            "node_info": {
                "type": self.nodes[node_id].node_type,
                "zone": self.nodes[node_id].zone,
                "criticality": self.nodes[node_id].criticality,
                "vulnerabilities": self.nodes[node_id].vulnerabilities
            }
        }
    
    def calculate_risk_likelihood(self, grs: float, k: float = 10.0, 
                                 threshold: float = 0.5) -> float:
        """Convert GRS to Risk Likelihood using sigmoid function
        
        Args:
            grs: Graph-Theoretic Risk Score (0-1)
            k: Steepness parameter (higher = more sensitive)
            threshold: Midpoint threshold (0-1)
        
        Returns:
            Risk likelihood probability (0-1)
        """
        # Sigmoid transformation: L(GRS) = 1 / (1 + e^(-k*(GRS - threshold)))
        import math
        
        try:
            likelihood = 1 / (1 + math.exp(-k * (grs - threshold)))
        except OverflowError:
            # Handle extreme values
            likelihood = 1.0 if grs > threshold else 0.0
        
        return likelihood
    
    def get_risk_classification(self, node_id: str) -> Dict[str, any]:
        """Get comprehensive risk classification for a node"""
        grs = self.compute_graph_theoretic_risk_score(node_id)
        likelihood = self.calculate_risk_likelihood(grs)
        
        # Risk level classification
        if likelihood < 0.2:
            risk_level = "Normal"
            priority = "Low"
        elif likelihood < 0.4:
            risk_level = "Low"
            priority = "Medium"
        elif likelihood < 0.6:
            risk_level = "Medium"
            priority = "Medium"
        elif likelihood < 0.8:
            risk_level = "High"
            priority = "High"
        else:
            risk_level = "Critical"
            priority = "Critical"
        
        # Get component scores
        nrs = self._calculate_node_risk_score(node_id)
        ers = self._calculate_edge_risk_score(node_id)
        prs = self._calculate_path_risk_score_for_node(node_id)
        
        return {
            "node_id": node_id,
            "grs": grs,
            "risk_likelihood": likelihood,
            "risk_level": risk_level,
            "priority": priority,
            "components": {
                "node_risk_score": nrs,
                "edge_risk_score": ers,
                "path_risk_score": prs
            },
            "node_info": {
                "type": self.nodes[node_id].node_type,
                "zone": self.nodes[node_id].zone,
                "criticality": self.nodes[node_id].criticality,
                "vulnerabilities": self.nodes[node_id].vulnerabilities
            }
        }
    
    def identify_critical_nodes(self, top_k: int = 5) -> List[Tuple[str, float]]:
        """Identify most critical nodes based on enhanced GRS"""
        node_risks = []
        
        for node_id in self.nodes:
            grs = self.compute_graph_theoretic_risk_score(node_id)
            likelihood = self.calculate_risk_likelihood(grs)
            node_risks.append((node_id, likelihood))
        
        return sorted(node_risks, key=lambda x: x[1], reverse=True)[:top_k]
    
    def generate_attack_graph(self) -> nx.DiGraph:
        """Generate attack graph based on vulnerabilities and connections"""
        self.attack_graph.clear()
        
        # Add all nodes from original graph
        for node_id, node_data in self.graph.nodes(data=True):
            self.attack_graph.add_node(node_id, **node_data)
        
        # Add edges based on attack feasibility
        for source, target, edge_data in self.graph.edges(data=True):
            # Calculate attack feasibility based on trust level and encryption
            feasibility = (1 - edge_data.get("trust_level", 0.5)) * (
                0.5 if edge_data.get("encrypted", False) else 1.0
            )
            
            if feasibility > 0.3:  # Threshold for viable attack edge
                self.attack_graph.add_edge(source, target, 
                                         attack_feasibility=feasibility,
                                         **edge_data)
        
        return self.attack_graph
    
    def visualize_network(self, output_path: str = "network_graph.png", 
                         highlight_critical: bool = True) -> None:
        """Visualize the ICS network with risk-based coloring"""
        plt.figure(figsize=(15, 10))
        
        # Calculate positions using spring layout
        pos = nx.spring_layout(self.graph, k=3, iterations=50)
        
        # Prepare node colors and sizes based on GRS
        node_colors = []
        node_sizes = []
        
        for node_id in self.graph.nodes():
            grs = self.compute_graph_theoretic_risk_score(node_id)
            
            # Color scale: green (low) to red (high)
            if grs < 0.3:
                color = 'lightgreen'
            elif grs < 0.6:
                color = 'yellow'
            elif grs < 0.8:
                color = 'orange'
            else:
                color = 'red'
            
            node_colors.append(color)
            node_sizes.append(300 + (grs * 700))  # Size based on risk
        
        # Draw the graph
        nx.draw(self.graph, pos, 
                node_color=node_colors,
                node_size=node_sizes,
                with_labels=True,
                font_size=8,
                font_weight='bold',
                arrows=True,
                edge_color='gray',
                alpha=0.8)
        
        # Add title and legend
        plt.title("ICS Network Security Graph\n(Node size and color indicate risk level)", 
                 fontsize=14, fontweight='bold')
        
        # Create legend
        legend_elements = [
            plt.scatter([], [], c='lightgreen', s=100, label='Low Risk (0-0.3)'),
            plt.scatter([], [], c='yellow', s=100, label='Medium Risk (0.3-0.6)'),
            plt.scatter([], [], c='orange', s=100, label='High Risk (0.6-0.8)'),
            plt.scatter([], [], c='red', s=100, label='Critical Risk (0.8-1.0)')
        ]
        plt.legend(handles=legend_elements, loc='upper right')
        
        plt.tight_layout()
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def export_analysis_results(self, output_dir: str = "graph_analysis") -> None:
        """Export graph analysis results to JSON files"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Export centrality measures
        centrality_data = self.calculate_centrality_measures()
        with open(f"{output_dir}/centrality_measures.json", 'w') as f:
            json.dump(centrality_data, f, indent=2)
        
        # Export GRS scores
        grs_scores = {node_id: self.compute_graph_theoretic_risk_score(node_id) 
                     for node_id in self.nodes}
        with open(f"{output_dir}/grs_scores.json", 'w') as f:
            json.dump(grs_scores, f, indent=2)
        
        # Export critical nodes
        critical_nodes = self.identify_critical_nodes(10)
        with open(f"{output_dir}/critical_nodes.json", 'w') as f:
            json.dump(critical_nodes, f, indent=2)
        
        # Export attack paths (sample)
        if len(self.nodes) >= 2:
            source_node = list(self.nodes.keys())[0]
            target_nodes = [node for node in self.nodes if node != source_node]
            
            all_attack_paths = []
            for target in target_nodes[:3]:  # Limit to first 3 targets
                paths = self.find_attack_paths(source_node, target, max_paths=5)
                all_attack_paths.extend([asdict(path) for path in paths])
            
            with open(f"{output_dir}/attack_paths.json", 'w') as f:
                json.dump(all_attack_paths, f, indent=2, default=str)
        
        print(f"Analysis results exported to {output_dir}/")

def main():
    """Demonstrate graph-theoretic ICS security analysis"""
    print("=== ICS Graph-Theoretic Security Analysis ===\n")
    
    # Initialize analyzer
    analyzer = ICSGraphAnalyzer()
    
    # Create sample network
    analyzer.create_sample_network()
    print(f"Created network with {len(analyzer.nodes)} nodes and {len(analyzer.edges)} edges")
    
    # Calculate centrality measures
    centrality = analyzer.calculate_centrality_measures()
    print(f"\nCentrality measures calculated for all nodes")
    
    # Identify critical nodes
    critical_nodes = analyzer.identify_critical_nodes(5)
    print(f"\nTop 5 Critical Nodes (by GRS):")
    for node_id, grs in critical_nodes:
        node = analyzer.nodes[node_id]
        print(f"  {node_id} ({node.node_type}): GRS = {grs:.3f}")
    
    # Find attack paths
    source = "FW-01"  # External entry point
    target = "PLC-01"  # Critical asset
    attack_paths = analyzer.find_attack_paths(source, target, max_paths=3)
    
    print(f"\nTop Attack Paths from {source} to {target}:")
    for path in attack_paths:
        print(f"  Path: {' -> '.join(path.nodes)}")
        print(f"    Risk: {path.total_risk:.3f}, Likelihood: {path.likelihood:.3f}")
        print(f"    Techniques: {', '.join(path.attack_techniques)}")
    
    # Generate attack graph
    attack_graph = analyzer.generate_attack_graph()
    print(f"\nAttack graph generated with {attack_graph.number_of_nodes()} nodes "
          f"and {attack_graph.number_of_edges()} attack edges")
    
    # Export results
    analyzer.export_analysis_results()
    
    # Visualize network (if matplotlib available)
    try:
        analyzer.visualize_network()
        print("Network visualization saved as 'network_graph.png'")
    except Exception as e:
        print(f"Visualization not available: {e}")

if __name__ == "__main__":
    main()