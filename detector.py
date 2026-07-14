import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
import ipaddress
from config import BRUTE_FORCE_THRESHOLD, TIME_WINDOW

class BruteForceDetector:
    def __init__(self):
        self.threshold = BRUTE_FORCE_THRESHOLD
        self.time_window = TIME_WINDOW
        # Common log patterns
        self.patterns = {
            'ssh_fail': re.compile(r'Failed password for .* from (\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
            'ssh_invalid': re.compile(r'Invalid user .* from (\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
            'ssh_connection': re.compile(r'Connection closed by (\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
            'apache_404': re.compile(r'(\d+\.\d+\.\d+\.\d+) .* "GET .* HTTP.*" 404', re.IGNORECASE),
            'apache_auth': re.compile(r'(\d+\.\d+\.\d+\.\d+) .* "GET .* HTTP.*" 401', re.IGNORECASE),
            'nginx_404': re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] "GET .* HTTP.*" 404', re.IGNORECASE),
            'nginx_auth': re.compile(r'(\d+\.\d+\.\d+\.\d+) - - \[.*\] "GET .* HTTP.*" 401', re.IGNORECASE),
            'generic_fail': re.compile(r'(?:failed|invalid|denied).*from\s*(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
        }
        
        # CVE patterns
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        self.exploit_indicators = [
            r'exploit', r'attack', r'malicious', r'suspicious',
            r'buffer overflow', r'sql injection', r'xss',
            r'remote code execution', r'rce', r'privilege escalation'
        ]
        
    def extract_ips(self, text):
        """Extract all IP addresses from text"""
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        raw_ips = ip_pattern.findall(text)
        valid_ips = []
        for ip in raw_ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except:
                continue
        return valid_ips
    
    def extract_cves(self, text):
        """Extract CVE references from text"""
        return self.cve_pattern.findall(text)
    
    def detect_brute_force(self, logs):
        """Detect brute force attempts from log entries"""
        ip_failures = defaultdict(list)
        failed_ips = set()
        detections = []
        
        # Process each line
        lines = logs.split('\n')
        for line in lines:
            timestamp = self.extract_timestamp(line)
            
            # Check for failure patterns
            for pattern_name, pattern in self.patterns.items():
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    if ip and self.is_valid_ip(ip):
                        ip_failures[ip].append(timestamp)
                        failed_ips.add(ip)
                        break
            
            # Also check for CVE references
            cves = self.extract_cves(line)
            if cves:
                # Check if any exploit indicators nearby
                for indicator in self.exploit_indicators:
                    if re.search(indicator, line, re.IGNORECASE):
                        # This might be an exploitation attempt
                        ips = self.extract_ips(line)
                        for ip in ips:
                            if self.is_valid_ip(ip):
                                ip_failures[ip].append(timestamp)
                                failed_ips.add(ip)
        
        # Analyze failure patterns
        results = []
        for ip, timestamps in ip_failures.items():
            if len(timestamps) >= self.threshold:
                # Sort timestamps
                sorted_times = sorted([t for t in timestamps if t is not None])
                
                # Check for time window violations
                if self.check_time_window(sorted_times):
                    # Get related CVEs
                    related_cves = self.extract_cves('\n'.join([line for line in lines if ip in line]))
                    
                    # Get failure details
                    details = self.get_failure_details(ip, lines)
                    
                    results.append({
                        'ip': ip,
                        'attempts': len(sorted_times),
                        'time_range': {
                            'first': sorted_times[0] if sorted_times else None,
                            'last': sorted_times[-1] if sorted_times else None
                        },
                        'cves': list(set(related_cves)) if related_cves else ['Unknown'],
                        'severity': self.calculate_severity(len(sorted_times), len(set(related_cves))),
                        'details': details
                    })
        
        return sorted(results, key=lambda x: x['attempts'], reverse=True)
    
    def detect_from_log(self, log_content):
        """Main detection function for log content"""
        return self.detect_brute_force(log_content)
    
    def extract_timestamp(self, line):
        """Extract timestamp from log line"""
        # Common timestamp patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})',
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})',
            r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                try:
                    return datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
                except:
                    continue
        return datetime.now()
    
    def is_valid_ip(self, ip):
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def check_time_window(self, timestamps):
        """Check if failures occur within the time window"""
        if not timestamps or len(timestamps) < self.threshold:
            return False
        
        # Check if threshold is met within time window
        for i in range(len(timestamps) - self.threshold + 1):
            time_diff = (timestamps[i + self.threshold - 1] - timestamps[i]).total_seconds()
            if time_diff <= self.time_window:
                return True
        return False
    
    def get_failure_details(self, ip, lines):
        """Get detailed failure information for an IP"""
        details = []
        for line in lines:
            if ip in line:
                # Check for specific error types
                if 'Failed password' in line or 'invalid' in line.lower():
                    details.append({
                        'line': line.strip(),
                        'type': 'Authentication Failure'
                    })
                elif '404' in line or 'Not Found' in line:
                    details.append({
                        'line': line.strip(),
                        'type': 'Resource Not Found'
                    })
                elif '401' in line or 'Unauthorized' in line:
                    details.append({
                        'line': line.strip(),
                        'type': 'Unauthorized Access'
                    })
                elif any(indicator in line.lower() for indicator in ['exploit', 'attack', 'malicious']):
                    details.append({
                        'line': line.strip(),
                        'type': 'Potential Attack'
                    })
        return details[:10]  # Limit to 10 details
    
    def calculate_severity(self, attempts, cve_count):
        """Calculate severity based on attempts and CVEs"""
        if attempts >= 100 or cve_count >= 5:
            return 'Critical'
        elif attempts >= 50 or cve_count >= 3:
            return 'High'
        elif attempts >= 20 or cve_count >= 1:
            return 'Medium'
        else:
            return 'Low'