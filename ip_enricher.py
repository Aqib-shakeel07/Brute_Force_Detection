import requests
import urllib3
import time
import json
from datetime import datetime, timedelta
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import (
    VIRUSTOTAL_API_KEY,
    ABUSEIPDB_API_KEY,
    VT_API_URL,
    ABUSEIPDB_API_URL,
    VT_RATE_LIMIT_PER_MINUTE,
    API_TIMEOUT,
    CACHE_DURATION,
    CACHE_FILE,
    CONFIDENCE_WEIGHTS,
    RISK_THRESHOLDS,
    LOG_FILE,
    ENABLE_API_ENRICHMENT,
    MAX_IPS_TO_ENRICH
)
import re

# Disable SSL warnings for development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Setup logging with UTF-8 encoding
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class IPEnricher:
    """Class to enrich IP data with external threat intelligence"""
    
    def __init__(self):
        self.vt_api_key = VIRUSTOTAL_API_KEY
        self.abuseipdb_api_key = ABUSEIPDB_API_KEY
        self.vt_base_url = VT_API_URL
        self.abuseipdb_base_url = ABUSEIPDB_API_URL
        self.cache_duration = CACHE_DURATION
        self.cache_file = CACHE_FILE
        self.cache = {}
        self.rate_limit_remaining = VT_RATE_LIMIT_PER_MINUTE
        self.last_request_time = datetime.now()
        
        # Load cache
        self.load_cache()
        
        # Check API keys
        if self.vt_api_key == 'your_virustotal_api_key_here':
            logger.warning("WARNING: VirusTotal API key not configured")
        if self.abuseipdb_api_key == 'your_abuseipdb_api_key_here':
            logger.warning("WARNING: AbuseIPDB API key not configured")
    
    def is_valid_ip(self, ip):
        """Check if the string is a valid IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(ip_pattern, ip) is not None
    
    def load_cache(self):
        """Load cached IP data from file"""
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                self.cache = json.load(f)
            logger.info(f"Loaded {len(self.cache)} cached IP entries")
        except FileNotFoundError:
            self.cache = {}
            logger.info("No cache file found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            self.cache = {}
    
    def save_cache(self):
        """Save cached IP data to file"""
        try:
            # Remove expired entries
            expired = []
            for key, value in self.cache.items():
                if 'timestamp' in value:
                    cache_time = datetime.fromisoformat(value['timestamp'])
                    if (datetime.now() - cache_time) > self.cache_duration:
                        expired.append(key)
            
            for key in expired:
                del self.cache[key]
            
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, indent=2)
            logger.info(f"Saved {len(self.cache)} IP entries to cache (removed {len(expired)} expired)")
        except Exception as e:
            logger.error(f"Error saving cache: {e}")
    
    def is_cached_valid(self, cache_key):
        """Check if cached data is still valid"""
        if cache_key not in self.cache:
            return False
        
        cache_time = datetime.fromisoformat(self.cache[cache_key]['timestamp'])
        return (datetime.now() - cache_time) <= self.cache_duration
    
    def get_virustotal_score(self, ip):
        """Fetch VirusTotal malicious count and details for an IP"""
        # Skip if not a valid IP
        if not self.is_valid_ip(ip):
            logger.warning(f"Skipping VirusTotal for invalid IP/hostname: {ip}")
            return None
        
        if not self.vt_api_key or self.vt_api_key == 'your_virustotal_api_key_here':
            return None
        
        cache_key = f"vt_{ip}"
        if self.is_cached_valid(cache_key):
            logger.info(f"Using cached VirusTotal data for {ip}")
            return self.cache[cache_key]['data']
        
        try:
            # Rate limiting
            self._enforce_rate_limit()
            
            url = f"{self.vt_base_url}/ip_addresses/{ip}"
            headers = {"x-apikey": self.vt_api_key}
            
            logger.info(f"Querying VirusTotal for IP: {ip}")
            
            # Disable SSL verification for development
            response = requests.get(url, headers=headers, timeout=API_TIMEOUT, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                result = {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'total_vendors': sum(stats.values()) if stats else 0,
                    'score': min(100, stats.get('malicious', 0) * 20),
                    'timestamp': datetime.now().isoformat()
                }
                
                # Cache the result
                self.cache[cache_key] = {
                    'data': result,
                    'timestamp': datetime.now().isoformat()
                }
                self.save_cache()
                
                return result
                
            elif response.status_code == 429:
                logger.warning(f"VirusTotal rate limit hit for {ip}")
                time.sleep(60)
                return self.get_virustotal_score(ip)
            else:
                logger.error(f"VirusTotal error {response.status_code} for {ip}: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"VirusTotal timeout for {ip}")
            return None
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL Error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching VirusTotal data for {ip}: {e}")
            return None
    
    def get_abuseipdb_score(self, ip):
        """Fetch AbuseIPDB confidence score and report details"""
        # Skip if not a valid IP
        if not self.is_valid_ip(ip):
            logger.warning(f"Skipping AbuseIPDB for invalid IP/hostname: {ip}")
            return None
        
        if not self.abuseipdb_api_key or self.abuseipdb_api_key == 'your_abuseipdb_api_key_here':
            return None
        
        cache_key = f"abuse_{ip}"
        if self.is_cached_valid(cache_key):
            logger.info(f"Using cached AbuseIPDB data for {ip}")
            return self.cache[cache_key]['data']
        
        try:
            url = f"{self.abuseipdb_base_url}/check"
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_api_key
            }
            
            logger.info(f"Querying AbuseIPDB for IP: {ip}")
            
            # Disable SSL verification for development
            response = requests.get(url, headers=headers, params=querystring, timeout=API_TIMEOUT, verify=False)
            
            if response.status_code == 200:
                data = response.json()
                abuse_data = data.get('data', {})
                
                result = {
                    'confidence_score': abuse_data.get('abuseConfidenceScore', 0),
                    'total_reports': abuse_data.get('totalReports', 0),
                    'country_code': abuse_data.get('countryCode', 'N/A'),
                    'isp': abuse_data.get('isp', 'N/A'),
                    'domain': abuse_data.get('domain', 'N/A'),
                    'usage_type': abuse_data.get('usageType', 'N/A'),
                    'reports': abuse_data.get('reports', [])[:5],
                    'timestamp': datetime.now().isoformat()
                }
                
                # Cache the result
                self.cache[cache_key] = {
                    'data': result,
                    'timestamp': datetime.now().isoformat()
                }
                self.save_cache()
                
                return result
                
            elif response.status_code == 429:
                logger.warning(f"AbuseIPDB rate limit hit for {ip}")
                time.sleep(60)
                return self.get_abuseipdb_score(ip)
            else:
                logger.error(f"AbuseIPDB error {response.status_code} for {ip}: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error(f"AbuseIPDB timeout for {ip}")
            return None
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL Error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error fetching AbuseIPDB data for {ip}: {e}")
            return None
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting for API calls"""
        now = datetime.now()
        if (now - self.last_request_time).total_seconds() < 60:
            self.rate_limit_remaining -= 1
            if self.rate_limit_remaining <= 0:
                wait_time = 60 - (now - self.last_request_time).total_seconds()
                if wait_time > 0:
                    logger.info(f"Rate limit reached, waiting {wait_time:.1f} seconds")
                    time.sleep(wait_time)
                    self.rate_limit_remaining = VT_RATE_LIMIT_PER_MINUTE
        else:
            self.rate_limit_remaining = VT_RATE_LIMIT_PER_MINUTE
        
        self.last_request_time = datetime.now()
    
    def enrich_ip_batch(self, ips, max_workers=3):
        """Enrich multiple IPs in parallel using ThreadPoolExecutor"""
        if not ips:
            return {}
        
        # Filter out invalid IPs (hostnames)
        valid_ips = [ip for ip in ips if self.is_valid_ip(ip)]
        invalid_ips = [ip for ip in ips if not self.is_valid_ip(ip)]
        
        if invalid_ips:
            logger.warning(f"Skipping {len(invalid_ips)} invalid IPs/hostnames: {invalid_ips[:5]}...")
        
        # Limit number of IPs to enrich
        if len(valid_ips) > MAX_IPS_TO_ENRICH:
            logger.info(f"Limiting enrichment to top {MAX_IPS_TO_ENRICH} IPs (out of {len(valid_ips)} valid IPs)")
            valid_ips = valid_ips[:MAX_IPS_TO_ENRICH]
        
        if not valid_ips:
            logger.warning("No valid IPs to enrich")
            return {}
        
        logger.info(f"Enriching {len(valid_ips)} IPs with {max_workers} workers")
        enriched_ips = {}
        
        def enrich_single_ip(ip):
            vt_data = self.get_virustotal_score(ip)
            abuse_data = self.get_abuseipdb_score(ip)
            return {
                'ip': ip,
                'virustotal': vt_data,
                'abuseipdb': abuse_data
            }
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(enrich_single_ip, ip): ip for ip in valid_ips}
            
            completed = 0
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    result = future.result()
                    enriched_ips[ip] = result
                    completed += 1
                    if completed % 10 == 0:
                        logger.info(f"Enriched {completed}/{len(valid_ips)} IPs")
                except Exception as e:
                    logger.error(f"Error enriching IP {ip}: {e}")
                    enriched_ips[ip] = {
                        'ip': ip,
                        'virustotal': None,
                        'abuseipdb': None
                    }
        
        logger.info(f"Successfully enriched {len(enriched_ips)} IPs")
        return enriched_ips
    
    def get_combined_score(self, ip_data):
        """Calculate combined threat score from all sources"""
        # Safely get values with None checks
        vt_data = ip_data.get('virustotal')
        abuse_data = ip_data.get('abuseipdb')
        
        vt_score = 0
        if vt_data and isinstance(vt_data, dict):
            vt_score = vt_data.get('score', 0)
        
        abuse_score = 0
        if abuse_data and isinstance(abuse_data, dict):
            abuse_score = abuse_data.get('confidence_score', 0)
        
        local_attempts = ip_data.get('attempt_count', 0)
        
        # Normalize scores to 0-100
        vt_normalized = vt_score
        abuse_normalized = abuse_score
        local_normalized = min(100, (local_attempts / 50) * 100)
        
        # Weighted average using config weights
        combined = (
            local_normalized * CONFIDENCE_WEIGHTS['attempts'] +
            vt_normalized * CONFIDENCE_WEIGHTS['virustotal'] +
            abuse_normalized * CONFIDENCE_WEIGHTS['abuseipdb']
        )
        
        return min(100, round(combined))
    
    def get_risk_level(self, score):
        """Determine risk level based on combined score"""
        if score >= RISK_THRESHOLDS['critical']:
            return 'CRITICAL'
        elif score >= RISK_THRESHOLDS['high']:
            return 'HIGH'
        elif score >= RISK_THRESHOLDS['medium']:
            return 'MEDIUM'
        else:
            return 'LOW'

# Singleton instance
_ip_enricher = None

def get_ip_enricher():
    global _ip_enricher
    if _ip_enricher is None:
        _ip_enricher = IPEnricher()
    return _ip_enricher