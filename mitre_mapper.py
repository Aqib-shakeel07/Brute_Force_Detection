# mitre_mapper.py
import json
import logging
import re
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class MitreMapper:
    """Map CVEs and attack patterns to MITRE ATT&CK framework"""
    
    def __init__(self):
        self.mitre_data = self._load_mitre_data()
        self.cve_to_technique = self._build_cve_mapping()
        self.attack_patterns = self._build_attack_patterns()
        self.cve_database = self._load_cve_database()
    
    def _load_mitre_data(self) -> Dict:
        """Load MITRE ATT&CK data"""
        return {
            'tactics': {
                'TA0001': {'name': 'Initial Access', 'color': '#dc2626', 'description': 'Techniques used to gain initial foothold'},
                'TA0002': {'name': 'Execution', 'color': '#f59e0b', 'description': 'Techniques used to run malicious code'},
                'TA0003': {'name': 'Persistence', 'color': '#f97316', 'description': 'Techniques used to maintain access'},
                'TA0004': {'name': 'Privilege Escalation', 'color': '#ef4444', 'description': 'Techniques used to gain higher-level permissions'},
                'TA0005': {'name': 'Defense Evasion', 'color': '#8b5cf6', 'description': 'Techniques used to avoid detection'},
                'TA0006': {'name': 'Credential Access', 'color': '#3b82f6', 'description': 'Techniques used to steal credentials'},
                'TA0007': {'name': 'Discovery', 'color': '#06b6d4', 'description': 'Techniques used to gather information'},
                'TA0008': {'name': 'Lateral Movement', 'color': '#ec4899', 'description': 'Techniques used to move through the network'},
                'TA0009': {'name': 'Collection', 'color': '#f59e0b', 'description': 'Techniques used to gather data'},
                'TA0010': {'name': 'Exfiltration', 'color': '#dc2626', 'description': 'Techniques used to steal data'},
                'TA0011': {'name': 'Command and Control', 'color': '#8b5cf6', 'description': 'Techniques used to communicate with compromised systems'},
                'TA0040': {'name': 'Impact', 'color': '#dc2626', 'description': 'Techniques used to disrupt or destroy systems'}
            },
            'techniques': {
                'T1046': {
                    'name': 'Network Service Scanning',
                    'tactic': 'TA0007',
                    'description': 'Scanning for open ports and services to identify vulnerabilities'
                },
                'T1110': {
                    'name': 'Brute Force',
                    'tactic': 'TA0006',
                    'description': 'Password guessing attacks using multiple attempts'
                },
                'T1133': {
                    'name': 'External Remote Services',
                    'tactic': 'TA0001',
                    'description': 'Access via external remote services like VPN, RDP, or SSH'
                },
                'T1078': {
                    'name': 'Valid Accounts',
                    'tactic': 'TA0001',
                    'description': 'Use of valid credentials to gain initial access'
                },
                'T1566': {
                    'name': 'Phishing',
                    'tactic': 'TA0001',
                    'description': 'Phishing attacks to steal credentials or deliver malware'
                },
                'T1048': {
                    'name': 'Exfiltration Over Alternative Protocol',
                    'tactic': 'TA0010',
                    'description': 'Data exfiltration using non-standard protocols'
                },
                'T1539': {
                    'name': 'Steal Web Session Cookie',
                    'tactic': 'TA0006',
                    'description': 'Session hijacking through stolen cookies'
                },
                'T1059': {
                    'name': 'Command and Scripting Interpreter',
                    'tactic': 'TA0002',
                    'description': 'Executing commands using scripting interpreters'
                },
                'T1021': {
                    'name': 'Remote Services',
                    'tactic': 'TA0008',
                    'description': 'Remote service exploitation like RDP, SMB, or WinRM'
                },
                'T1071': {
                    'name': 'Application Layer Protocol',
                    'tactic': 'TA0011',
                    'description': 'C2 communication using standard application protocols'
                },
                'T1190': {
                    'name': 'Exploit Public-Facing Application',
                    'tactic': 'TA0001',
                    'description': 'Exploiting vulnerabilities in public-facing applications'
                },
                'T1203': {
                    'name': 'Exploitation for Client Execution',
                    'tactic': 'TA0002',
                    'description': 'Exploiting vulnerabilities in client applications'
                },
                'T1210': {
                    'name': 'Exploitation of Remote Services',
                    'tactic': 'TA0008',
                    'description': 'Exploiting remote service vulnerabilities'
                },
                'T1486': {
                    'name': 'Data Encrypted for Impact',
                    'tactic': 'TA0040',
                    'description': 'Ransomware encryption of data'
                },
                'T1490': {
                    'name': 'Inhibit System Recovery',
                    'tactic': 'TA0040',
                    'description': 'Deleting backups or recovery points'
                },
                'T1053': {
                    'name': 'Scheduled Task/Job',
                    'tactic': 'TA0003',
                    'description': 'Scheduling tasks for persistence or execution'
                },
                'T1543': {
                    'name': 'Create or Modify System Process',
                    'tactic': 'TA0003',
                    'description': 'Creating or modifying system processes for persistence'
                },
                'T1562': {
                    'name': 'Impair Defenses',
                    'tactic': 'TA0005',
                    'description': 'Disabling security tools or defenses'
                },
                'T1574': {
                    'name': 'Hijack Execution Flow',
                    'tactic': 'TA0005',
                    'description': 'Hijacking execution flow for persistence or evasion'
                }
            }
        }
    
    def _build_cve_mapping(self) -> Dict:
        """Build CVE to MITRE technique mapping"""
        return {
            # Brute Force related CVEs
            'CVE-2024-1234': ['T1110', 'T1078'],
            'CVE-2024-5678': ['T1110', 'T1046'],
            'CVE-2024-9012': ['T1133', 'T1078'],
            'CVE-2024-4321': ['T1190', 'T1203'],
            'CVE-2024-8765': ['T1210', 'T1021'],
            'CVE-2024-2468': ['T1486', 'T1490'],
            'CVE-2024-1357': ['T1059', 'T1053'],
            'CVE-2024-8642': ['T1566', 'T1078'],
            
            # Default mapping for common patterns
            'brute_force': ['T1110'],
            'credential_stuffing': ['T1110', 'T1078'],
            'password_spray': ['T1110'],
            'dictionary_attack': ['T1110'],
            'remote_access': ['T1133', 'T1078'],
            'phishing': ['T1566'],
            'exfiltration': ['T1048'],
            'ransomware': ['T1486', 'T1490'],
            'exploit': ['T1190', 'T1203'],
            'lateral_movement': ['T1210', 'T1021'],
            'persistence': ['T1053', 'T1543'],
            'defense_evasion': ['T1562', 'T1574']
        }
    
    def _build_attack_patterns(self) -> Dict:
        """Build attack pattern classification"""
        return {
            'brute_force': {
                'technique': 'T1110',
                'technique_name': 'Brute Force',
                'tactic': 'TA0006',
                'tactic_name': 'Credential Access',
                'severity': 'HIGH',
                'description': 'Multiple failed login attempts detected'
            },
            'credential_stuffing': {
                'technique': 'T1110',
                'technique_name': 'Brute Force',
                'tactic': 'TA0006',
                'tactic_name': 'Credential Access',
                'severity': 'HIGH',
                'description': 'Credential stuffing attack detected'
            },
            'password_spray': {
                'technique': 'T1110',
                'technique_name': 'Brute Force',
                'tactic': 'TA0006',
                'tactic_name': 'Credential Access',
                'severity': 'HIGH',
                'description': 'Password spray attack detected'
            },
            'remote_scan': {
                'technique': 'T1046',
                'technique_name': 'Network Service Scanning',
                'tactic': 'TA0007',
                'tactic_name': 'Discovery',
                'severity': 'MEDIUM',
                'description': 'Network scanning activity detected'
            },
            'external_access': {
                'technique': 'T1133',
                'technique_name': 'External Remote Services',
                'tactic': 'TA0001',
                'tactic_name': 'Initial Access',
                'severity': 'MEDIUM',
                'description': 'External remote access detected'
            },
            'phishing': {
                'technique': 'T1566',
                'technique_name': 'Phishing',
                'tactic': 'TA0001',
                'tactic_name': 'Initial Access',
                'severity': 'HIGH',
                'description': 'Phishing activity detected'
            },
            'ransomware': {
                'technique': 'T1486',
                'technique_name': 'Data Encrypted for Impact',
                'tactic': 'TA0040',
                'tactic_name': 'Impact',
                'severity': 'CRITICAL',
                'description': 'Ransomware activity detected'
            },
            'lateral_movement': {
                'technique': 'T1210',
                'technique_name': 'Exploitation of Remote Services',
                'tactic': 'TA0008',
                'tactic_name': 'Lateral Movement',
                'severity': 'HIGH',
                'description': 'Lateral movement detected'
            },
            'persistence': {
                'technique': 'T1053',
                'technique_name': 'Scheduled Task/Job',
                'tactic': 'TA0003',
                'tactic_name': 'Persistence',
                'severity': 'MEDIUM',
                'description': 'Persistence mechanism detected'
            }
        }
    
    def _load_cve_database(self) -> Dict:
        """Load CVE database with descriptions"""
        return {
            'CVE-2024-1234': {
                'description': 'SolarWinds Orion Platform vulnerability allowing remote code execution',
                'severity': 'CRITICAL',
                'cvss_score': 9.8
            },
            'CVE-2024-5678': {
                'description': 'SolarWinds Orion Platform information disclosure vulnerability',
                'severity': 'HIGH',
                'cvss_score': 7.5
            },
            'CVE-2024-9012': {
                'description': 'SolarWinds Orion Platform authentication bypass vulnerability',
                'severity': 'CRITICAL',
                'cvss_score': 9.1
            },
            'CVE-2024-4321': {
                'description': 'SolarWinds Orion Platform SQL injection vulnerability',
                'severity': 'HIGH',
                'cvss_score': 8.5
            }
        }
    
    def map_cve(self, cve_id: str) -> Dict:
        """Map a CVE to MITRE ATT&CK techniques"""
        # Check if CVE exists in database
        cve_data = self.cve_database.get(cve_id, {})
        
        # Get techniques from mapping
        techniques = self.cve_to_technique.get(cve_id, [])
        if not techniques:
            # Try to infer from CVE description
            techniques = self._infer_techniques(cve_id, cve_data)
        
        return self._get_technique_details(techniques, cve_data)
    
    def map_attack_pattern(self, pattern: str) -> Dict:
        """Map an attack pattern to MITRE ATT&CK"""
        pattern_lower = pattern.lower()
        
        # Check exact match
        if pattern_lower in self.attack_patterns:
            return self.attack_patterns[pattern_lower]
        
        # Check partial match
        for key, value in self.attack_patterns.items():
            if key in pattern_lower:
                return value
        
        # Check for keywords
        keywords = {
            'brute': 'brute_force',
            'credential': 'credential_stuffing',
            'password': 'password_spray',
            'scan': 'remote_scan',
            'remote': 'remote_access',
            'phish': 'phishing',
            'ransom': 'ransomware',
            'lateral': 'lateral_movement',
            'persist': 'persistence'
        }
        
        for keyword, pattern_type in keywords.items():
            if keyword in pattern_lower:
                return self.attack_patterns.get(pattern_type, self._get_default_mapping())
        
        return self._get_default_mapping()
    
    def _infer_techniques(self, cve_id: str, cve_data: Dict) -> List[str]:
        """Infer MITRE techniques from CVE data"""
        cve_lower = cve_id.lower()
        description = cve_data.get('description', '').lower()
        
        # Check for keywords in CVE ID or description
        if 'brute' in cve_lower or 'force' in cve_lower or 'brute' in description or 'force' in description:
            return ['T1110']
        if 'credential' in cve_lower or 'password' in cve_lower or 'credential' in description:
            return ['T1110', 'T1078']
        if 'remote' in cve_lower or 'external' in cve_lower or 'remote' in description:
            return ['T1133']
        if 'scan' in cve_lower or 'discovery' in cve_lower or 'scan' in description:
            return ['T1046']
        if 'exploit' in cve_lower or 'exploit' in description:
            return ['T1190', 'T1203']
        if 'sql' in cve_lower or 'injection' in cve_lower or 'sql' in description:
            return ['T1190']
        if 'auth' in cve_lower or 'bypass' in cve_lower or 'auth' in description:
            return ['T1078']
        if 'exec' in cve_lower or 'code' in cve_lower or 'exec' in description:
            return ['T1059']
        
        return ['T1078']  # Default: Valid Accounts
    
    def _get_technique_details(self, technique_ids: List[str], cve_data: Dict = None) -> Dict:
        """Get detailed information for techniques"""
        techniques = []
        
        for tech_id in technique_ids:
            tech = self.mitre_data['techniques'].get(tech_id, {})
            if tech:
                tactic = self.mitre_data['tactics'].get(tech.get('tactic', ''), {})
                techniques.append({
                    'id': tech_id,
                    'name': tech.get('name', tech_id),
                    'tactic': tech.get('tactic', 'Unknown'),
                    'tactic_name': tactic.get('name', 'Unknown'),
                    'tactic_color': tactic.get('color', '#667eea'),
                    'description': tech.get('description', 'No description available'),
                    'tactic_description': tactic.get('description', '')
                })
        
        return {
            'techniques': techniques,
            'count': len(techniques),
            'cve_data': cve_data or {}
        }
    
    def _get_default_mapping(self) -> Dict:
        """Get default mapping when no specific match found"""
        return {
            'technique': 'T1078',
            'technique_name': 'Valid Accounts',
            'tactic': 'TA0001',
            'tactic_name': 'Initial Access',
            'severity': 'MEDIUM',
            'description': 'Potential use of valid credentials for unauthorized access'
        }
    
    def get_tactic_summary(self, cves: List[Dict]) -> Dict:
        """Get summary of tactics used across CVEs"""
        tactics_summary = {}
        
        for cve in cves:
            cve_id = cve.get('id', '')
            mapping = self.map_cve(cve_id)
            for technique in mapping.get('techniques', []):
                tactic_name = technique.get('tactic_name', 'Unknown')
                if tactic_name not in tactics_summary:
                    tactics_summary[tactic_name] = {
                        'count': 0,
                        'color': technique.get('tactic_color', '#667eea'),
                        'techniques': [],
                        'cves': []
                    }
                tactics_summary[tactic_name]['count'] += 1
                # Add unique techniques
                if technique['name'] not in [t['name'] for t in tactics_summary[tactic_name]['techniques']]:
                    tactics_summary[tactic_name]['techniques'].append(technique)
                # Add CVE if not already added
                if cve_id not in tactics_summary[tactic_name]['cves']:
                    tactics_summary[tactic_name]['cves'].append(cve_id)
        
        return tactics_summary
    
    def get_mitre_matrix(self) -> Dict:
        """Get full MITRE ATT&CK matrix"""
        return self.mitre_data
    
    def get_technique_details(self, technique_id: str) -> Dict:
        """Get details for a specific technique"""
        tech = self.mitre_data['techniques'].get(technique_id, {})
        if tech:
            tactic = self.mitre_data['tactics'].get(tech.get('tactic', ''), {})
            return {
                'id': technique_id,
                'name': tech.get('name', technique_id),
                'tactic': tech.get('tactic', 'Unknown'),
                'tactic_name': tactic.get('name', 'Unknown'),
                'tactic_color': tactic.get('color', '#667eea'),
                'description': tech.get('description', 'No description available'),
                'tactic_description': tactic.get('description', '')
            }
        return None
    
    def search_techniques(self, query: str) -> List[Dict]:
        """Search for techniques by keyword"""
        query_lower = query.lower()
        results = []
        
        for tech_id, tech in self.mitre_data['techniques'].items():
            if (query_lower in tech.get('name', '').lower() or 
                query_lower in tech.get('description', '').lower() or
                query_lower in tech_id.lower()):
                results.append({
                    'id': tech_id,
                    'name': tech.get('name', tech_id),
                    'description': tech.get('description', ''),
                    'tactic': tech.get('tactic', 'Unknown')
                })
        
        return results
    
    def get_attack_lifecycle(self, patterns: List[str]) -> Dict:
        """Map multiple patterns to attack lifecycle stages"""
        lifecycle = {
            'reconnaissance': [],
            'initial_access': [],
            'execution': [],
            'persistence': [],
            'privilege_escalation': [],
            'defense_evasion': [],
            'credential_access': [],
            'discovery': [],
            'lateral_movement': [],
            'collection': [],
            'command_and_control': [],
            'exfiltration': [],
            'impact': []
        }
        
        tactic_to_stage = {
            'TA0007': 'reconnaissance',
            'TA0001': 'initial_access',
            'TA0002': 'execution',
            'TA0003': 'persistence',
            'TA0004': 'privilege_escalation',
            'TA0005': 'defense_evasion',
            'TA0006': 'credential_access',
            'TA0007': 'discovery',
            'TA0008': 'lateral_movement',
            'TA0009': 'collection',
            'TA0011': 'command_and_control',
            'TA0010': 'exfiltration',
            'TA0040': 'impact'
        }
        
        for pattern in patterns:
            mapping = self.map_attack_pattern(pattern)
            if mapping:
                tactic = mapping.get('tactic', '')
                stage = tactic_to_stage.get(tactic, 'unknown')
                if stage in lifecycle:
                    lifecycle[stage].append(mapping)
        
        return lifecycle

# Singleton instance
_mitre_mapper = None

def get_mitre_mapper():
    global _mitre_mapper
    if _mitre_mapper is None:
        _mitre_mapper = MitreMapper()
    return _mitre_mapper