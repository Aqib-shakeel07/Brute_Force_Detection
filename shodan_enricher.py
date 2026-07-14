# shodan_enricher.py
import shodan
import json
import logging
from config import DATA_FOLDER, SHODAN_API_KEY

logger = logging.getLogger(__name__)

class ShodanEnricher:
    """Shodan device information enricher"""
    
    def __init__(self):
        self.api_key = SHODAN_API_KEY
        self.cache_file = f'{DATA_FOLDER}/shodan_cache.json'
        self.cache = {}
        self.load_cache()
        
        # Initialize Shodan API
        if self.api_key and self.api_key != 'your_shodan_api_key_here':
            try:
                self.api = shodan.Shodan(self.api_key)
                logger.info("Shodan API initialized successfully")
            except Exception as e:
                logger.error(f"Shodan init error: {e}")
                self.api = None
        else:
            logger.warning("Shodan API key not configured")
            self.api = None
    
    def load_cache(self):
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
            logger.info(f"Loaded {len(self.cache)} Shodan cache entries")
        except:
            self.cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
            logger.info(f"Saved {len(self.cache)} Shodan cache entries")
        except Exception as e:
            logger.error(f"Error saving Shodan cache: {e}")
    
    def get_device_info(self, ip):
        """Get device information from Shodan"""
        if not self.api:
            return None
        
        # Check cache
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            # Query Shodan
            result = self.api.host(ip)
            
            # Extract relevant information
            device_info = {
                'hostnames': result.get('hostnames', []),
                'ports': result.get('ports', []),
                'vulnerabilities': result.get('vulns', []),
                'services': [],
                'os': result.get('os', 'Unknown'),
                'isp': result.get('isp', 'Unknown'),
                'country': result.get('country_name', 'Unknown'),
                'latitude': result.get('latitude', 0),
                'longitude': result.get('longitude', 0),
                'products': [],
                'updated': result.get('updated', None)
            }
            
            # Parse services
            for service in result.get('data', []):
                service_info = {
                    'port': service.get('port'),
                    'service': service.get('service', 'Unknown'),
                    'product': service.get('product', 'Unknown'),
                    'version': service.get('version', 'Unknown'),
                    'banner': service.get('banner', '')[:200]  # Truncate banner
                }
                device_info['services'].append(service_info)
                
                if service_info['product'] and service_info['product'] not in device_info['products']:
                    device_info['products'].append(service_info['product'])
            
            # Cache the result
            self.cache[ip] = device_info
            self.save_cache()
            
            return device_info
            
        except shodan.APIError as e:
            logger.error(f"Shodan API error for {ip}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting Shodan data for {ip}: {e}")
            return None

# Singleton instance
_shodan_enricher = None

def get_shodan_enricher():
    global _shodan_enricher
    if _shodan_enricher is None:
        _shodan_enricher = ShodanEnricher()
    return _shodan_enricher