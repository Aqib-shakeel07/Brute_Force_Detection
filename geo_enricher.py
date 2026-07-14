# geo_enricher.py
import requests
import json
import logging
from config import DATA_FOLDER

logger = logging.getLogger(__name__)

class GeoEnricher:
    """Geolocation and IP intelligence enricher"""
    
    def __init__(self):
        self.cache_file = f'{DATA_FOLDER}/geo_cache.json'
        self.cache = {}
        self.load_cache()
        
        # Free IP geolocation APIs (can be upgraded to paid)
        self.geo_apis = [
            {
                'name': 'ip-api',
                'url': 'http://ip-api.com/json/{ip}',
                'params': {'fields': 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query'}
            },
            {
                'name': 'ipinfo',
                'url': 'https://ipinfo.io/{ip}/json',
                'params': {}
            }
        ]
    
    def load_cache(self):
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
            logger.info(f"Loaded {len(self.cache)} geo cache entries")
        except:
            self.cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
            logger.info(f"Saved {len(self.cache)} geo cache entries")
        except Exception as e:
            logger.error(f"Error saving geo cache: {e}")
    
    def get_geolocation(self, ip):
        """Get geolocation data for an IP"""
        # Check cache first
        if ip in self.cache:
            return self.cache[ip]
        
        # Skip if not a valid IP
        if not self.is_valid_ip(ip):
            return None
        
        # Try primary API
        try:
            response = requests.get(
                self.geo_apis[0]['url'].format(ip=ip),
                params=self.geo_apis[0]['params'],
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') != 'fail':
                    result = {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'zip': data.get('zip', 'Unknown'),
                        'latitude': data.get('lat', 0),
                        'longitude': data.get('lon', 0),
                        'timezone': data.get('timezone', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'asn': data.get('as', 'Unknown'),
                        'source': 'ip-api'
                    }
                    
                    # Cache the result
                    self.cache[ip] = result
                    self.save_cache()
                    return result
        except Exception as e:
            logger.error(f"Error getting geolocation for {ip}: {e}")
        
        return None
    
    def is_valid_ip(self, ip):
        """Check if string is a valid IP address"""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return re.match(ip_pattern, ip) is not None

# Singleton instance
_geo_enricher = None

def get_geo_enricher():
    global _geo_enricher
    if _geo_enricher is None:
        _geo_enricher = GeoEnricher()
    return _geo_enricher