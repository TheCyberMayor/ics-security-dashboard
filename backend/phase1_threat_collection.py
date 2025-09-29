"""
ICS Cybersecurity Framework - Phase 1: Threat Identification and Data Collection
Implements data collection from multiple sources following MITRE ATT&CK for ICS
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import aiohttp
import csv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ThreatIntelligence:
    """Structured threat intelligence data"""
    threat_id: str
    name: str
    description: str
    mitre_technique: str
    severity: str
    source: str
    timestamp: datetime
    indicators: Dict[str, Any]
    affected_systems: List[str]

@dataclass
class ICSEvent:
    """Industrial control system event"""
    event_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    protocol: str
    function_code: Optional[str]
    data_payload: Optional[str]
    anomaly_score: float
    system_type: str  # PLC, HMI, SCADA, etc.

class ThreatDataCollector:
    """Collects threat data from multiple sources"""
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.mitre_mapping = self._load_mitre_mapping()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration for data sources"""
        default_config = {
            "mitre_api": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
            "cve_api": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "ics_cert_feed": "https://us-cert.cisa.gov/ics/advisories.xml",
            "collection_interval": 300,  # 5 minutes
            "data_retention_days": 30
        }
        
        try:
            with open(config_path, 'r') as f:
                return {**default_config, **json.load(f)}
        except FileNotFoundError:
            logger.warning(f"Config file {config_path} not found, using defaults")
            return default_config
    
    def _load_mitre_mapping(self) -> Dict[str, Dict]:
        """Load MITRE ATT&CK for ICS technique mapping"""
        # Simplified mapping - in production, load from MITRE CTI repository
        return {
            "T0855": {
                "name": "Unauthorized Command Message",
                "description": "Adversaries may send unauthorized command messages to control system devices",
                "tactics": ["Impact", "Inhibit Response Function"],
                "severity": "high"
            },
            "T0856": {
                "name": "Spoof Reporting Message", 
                "description": "Adversaries may spoof reporting messages in control systems",
                "tactics": ["Impact", "Impair Process Control"],
                "severity": "medium"
            },
            "T0883": {
                "name": "Internet Accessible Device",
                "description": "Adversaries may gain access through internet-accessible devices",
                "tactics": ["Initial Access"],
                "severity": "high"
            },
            "T0859": {
                "name": "Valid Accounts",
                "description": "Adversaries may obtain valid accounts to gain access",
                "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                "severity": "medium"
            }
        }
    
    async def collect_mitre_threats(self) -> List[ThreatIntelligence]:
        """Collect MITRE ATT&CK for ICS techniques"""
        threats = []
        
        for technique_id, data in self.mitre_mapping.items():
            threat = ThreatIntelligence(
                threat_id=technique_id,
                name=data["name"],
                description=data["description"],
                mitre_technique=technique_id,
                severity=data["severity"],
                source="MITRE_ICS",
                timestamp=datetime.now(),
                indicators={"tactics": data["tactics"]},
                affected_systems=["PLC", "HMI", "SCADA", "RTU"]
            )
            threats.append(threat)
        
        logger.info(f"Collected {len(threats)} MITRE ICS techniques")
        return threats
    
    async def collect_cve_data(self, days_back: int = 7) -> List[ThreatIntelligence]:
        """Collect recent CVE data for industrial systems"""
        threats = []
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        # Simulate CVE collection - in production, use NVD API
        simulated_cves = [
            {
                "id": "CVE-2023-1001",
                "description": "Buffer overflow in Modbus TCP implementation",
                "severity": "critical",
                "cvss_score": 9.8,
                "affected_products": ["Schneider Electric", "Siemens"]
            },
            {
                "id": "CVE-2023-1002", 
                "description": "Authentication bypass in HMI software",
                "severity": "high",
                "cvss_score": 8.1,
                "affected_products": ["Rockwell Automation", "ABB"]
            }
        ]
        
        for cve in simulated_cves:
            threat = ThreatIntelligence(
                threat_id=cve["id"],
                name=f"CVE: {cve['description']}",
                description=cve["description"],
                mitre_technique="T0883",  # Map to relevant technique
                severity=cve["severity"],
                source="CVE_DATABASE",
                timestamp=datetime.now(),
                indicators={"cvss_score": cve["cvss_score"]},
                affected_systems=cve["affected_products"]
            )
            threats.append(threat)
        
        logger.info(f"Collected {len(threats)} CVE entries")
        return threats
    
    def simulate_packet_capture(self, duration_minutes: int = 5) -> List[ICSEvent]:
        """Simulate packet capture from ICS network"""
        import random
        
        events = []
        protocols = ["Modbus", "DNP3", "EtherNet/IP", "PROFINET"]
        system_types = ["PLC", "HMI", "SCADA", "RTU", "Historian"]
        
        # Generate simulated network events
        for i in range(100):  # Simulate 100 events
            event = ICSEvent(
                event_id=f"NET_{i:06d}",
                timestamp=datetime.now() - timedelta(minutes=random.randint(0, duration_minutes)),
                source_ip=f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
                dest_ip=f"10.0.{random.randint(1,5)}.{random.randint(1,254)}",
                protocol=random.choice(protocols),
                function_code=f"0x{random.randint(1,255):02X}",
                data_payload=f"payload_{random.randint(1000,9999)}",
                anomaly_score=random.uniform(0.0, 1.0),
                system_type=random.choice(system_types)
            )
            events.append(event)
        
        logger.info(f"Simulated {len(events)} network events")
        return events
    
    async def collect_all_threats(self) -> Dict[str, List]:
        """Collect threats from all configured sources"""
        logger.info("Starting comprehensive threat data collection")
        
        # Collect from multiple sources concurrently
        mitre_task = self.collect_mitre_threats()
        cve_task = self.collect_cve_data()
        
        mitre_threats, cve_threats = await asyncio.gather(mitre_task, cve_task)
        
        # Simulate packet capture (synchronous)
        network_events = self.simulate_packet_capture()
        
        return {
            "mitre_threats": mitre_threats,
            "cve_threats": cve_threats,
            "network_events": network_events
        }
    
    def export_to_csv(self, data: Dict[str, List], output_dir: str = "data"):
        """Export collected data to CSV files"""
        Path(output_dir).mkdir(exist_ok=True)
        
        # Export threats
        threat_data = data["mitre_threats"] + data["cve_threats"]
        with open(f"{output_dir}/threats.csv", 'w', newline='', encoding='utf-8') as f:
            if threat_data:
                writer = csv.DictWriter(f, fieldnames=asdict(threat_data[0]).keys())
                writer.writeheader()
                for threat in threat_data:
                    writer.writerow(asdict(threat))
        
        # Export network events
        with open(f"{output_dir}/network_events.csv", 'w', newline='', encoding='utf-8') as f:
            if data["network_events"]:
                writer = csv.DictWriter(f, fieldnames=asdict(data["network_events"][0]).keys())
                writer.writeheader()
                for event in data["network_events"]:
                    writer.writerow(asdict(event))
        
        logger.info(f"Data exported to {output_dir}/ directory")

async def main():
    """Main function to demonstrate threat data collection"""
    collector = ThreatDataCollector()
    
    # Collect all threat data
    data = await collector.collect_all_threats()
    
    # Export to CSV for analysis
    collector.export_to_csv(data)
    
    # Print summary
    print(f"\n=== Threat Data Collection Summary ===")
    print(f"MITRE ICS Techniques: {len(data['mitre_threats'])}")
    print(f"CVE Entries: {len(data['cve_threats'])}")
    print(f"Network Events: {len(data['network_events'])}")
    print(f"Total Threat Indicators: {len(data['mitre_threats']) + len(data['cve_threats'])}")
    
    return data

if __name__ == "__main__":
    asyncio.run(main())