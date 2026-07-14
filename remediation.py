# remediation.py
import ipaddress
from typing import Dict, List, Any
import platform

class RemediationEngine:
    """Generate remediation steps for suspicious IPs"""
    
    def __init__(self):
        self.os_type = self._detect_os()
    
    def _detect_os(self):
        """Detect the operating system"""
        os_name = platform.system()
        if os_name == 'Windows':
            return 'windows'
        elif os_name == 'Linux':
            return 'linux'
        elif os_name == 'Darwin':
            return 'macos'
        return 'unknown'
    
    def get_remediation_plan(self, ip: str, threat_data: Dict = None) -> Dict:
        """Generate complete remediation plan for an IP"""
        
        is_private = self._is_private_ip(ip)
        ip_type = 'private' if is_private else 'public'
        risk_level = threat_data.get('risk_level', 'MEDIUM') if threat_data else 'MEDIUM'
        
        return {
            'ip': ip,
            'ip_type': ip_type,
            'country': threat_data.get('country', 'Unknown') if threat_data else 'Unknown',
            'risk_level': risk_level,
            'threat_data': threat_data or {},
            'remediation_steps': self._get_remediation_steps(ip, risk_level, is_private),
            'blocking_steps': self._get_blocking_steps(ip, risk_level, is_private),
            'protection_steps': self._get_protection_steps(ip, risk_level, is_private),
            'best_practices': self._get_best_practices()
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def _get_remediation_steps(self, ip: str, risk_level: str, is_private: bool) -> List[Dict]:
        steps = [
            {
                'title': 'Verify the Attack',
                'description': 'Confirm that the suspicious activity is indeed malicious and not a false positive. Check logs for patterns.'
            },
            {
                'title': 'Isolate the Threat',
                'description': f'Immediately isolate the source IP {ip} from critical systems to prevent further damage.'
            },
            {
                'title': 'Reset Credentials',
                'description': 'Reset passwords for any accounts that may have been compromised by this IP.'
            },
            {
                'title': 'Review Logs',
                'description': f'Check all logs for activity from {ip} in the last 7 days to assess the scope of the attack.'
            }
        ]
        
        if risk_level in ['CRITICAL', 'HIGH']:
            steps.insert(1, {
                'title': 'Emergency Response',
                'description': f'⚠️ HIGH RISK: Immediately block {ip} at the firewall level and alert the security team.'
            })
        
        if is_private:
            steps.append({
                'title': 'Check Internal Systems',
                'description': f'Private IP detected. Check if any internal systems have been compromised. Investigate {ip}'
            })
        
        return steps
    
    def _get_blocking_steps(self, ip: str, risk_level: str, is_private: bool) -> List[Dict]:
        os_type = self.os_type
        commands = []
        
        if os_type == 'windows':
            commands = [
                {
                    'title': 'Block IP using Windows Firewall',
                    'description': f'Add a firewall rule to block {ip}',
                    'command': f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
                },
                {
                    'title': 'Block IP using PowerShell',
                    'description': f'Block {ip} using PowerShell',
                    'command': f'New-NetFirewallRule -DisplayName "Block_{ip}" -Direction Inbound -Action Block -RemoteAddress {ip}'
                },
                {
                    'title': 'Block IP in Hosts File',
                    'description': f'Add {ip} to hosts file',
                    'command': f'echo 0.0.0.0 {ip} >> C:\\Windows\\System32\\drivers\\etc\\hosts'
                }
            ]
        elif os_type == 'linux' or os_type == 'macos':
            commands = [
                {
                    'title': 'Block IP using iptables',
                    'description': f'Add a firewall rule to block {ip}',
                    'command': f'sudo iptables -A INPUT -s {ip} -j DROP'
                },
                {
                    'title': 'Block IP using UFW',
                    'description': f'Block {ip} using UFW firewall',
                    'command': f'sudo ufw deny from {ip}'
                }
            ]
        else:
            commands = [
                {
                    'title': 'Block IP at Network Level',
                    'description': f'Contact your network administrator to block {ip} at the network perimeter.'
                }
            ]
        
        commands.append({
            'title': 'Block at Cloud Provider Level',
            'description': 'Add IP to Security Groups or Network Security Groups',
            'command': f'aws ec2 revoke-security-group-ingress --group-id sg-xxxxx --protocol tcp --port 22 --cidr {ip}/32'
        })
        
        return commands
    
    def _get_protection_steps(self, ip: str, risk_level: str, is_private: bool) -> List[Dict]:
        steps = [
            {
                'title': 'Enable Rate Limiting',
                'description': 'Implement rate limiting to prevent brute force attacks.'
            },
            {
                'title': 'Enable 2FA/MFA',
                'description': 'Require multi-factor authentication for all critical accounts.'
            },
            {
                'title': 'Regular Security Audits',
                'description': 'Conduct regular security audits to identify vulnerabilities.'
            },
            {
                'title': 'Threat Intelligence Feed',
                'description': 'Subscribe to threat intelligence feeds to automatically block known malicious IPs.'
            }
        ]
        
        if is_private:
            steps.append({
                'title': 'Internal Network Segmentation',
                'description': 'Segment your internal network to limit lateral movement of threats.'
            })
        
        return steps
    
    def _get_best_practices(self) -> List[Dict]:
        return [
            {
                'title': 'Zero Trust Architecture',
                'description': 'Never trust, always verify. Every access request should be authenticated and authorized.'
            },
            {
                'title': 'Principle of Least Privilege',
                'description': 'Give users and systems only the permissions they need to function.'
            },
            {
                'title': 'Regular Backups',
                'description': 'Maintain regular backups of critical data to recover from attacks.'
            },
            {
                'title': 'Security Training',
                'description': 'Train employees to recognize phishing attempts and security threats.'
            },
            {
                'title': 'Incident Response Plan',
                'description': 'Have a documented and tested incident response plan in place.'
            },
            {
                'title': 'Continuous Monitoring',
                'description': 'Implement continuous security monitoring and alerting systems.'
            }
        ]

_remediation_engine = None

def get_remediation_engine():
    global _remediation_engine
    if _remediation_engine is None:
        _remediation_engine = RemediationEngine()
    return _remediation_engine