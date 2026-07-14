# whois_enricher.py
import whois
import json
import logging
from datetime import datetime
from config import DATA_FOLDER

logger = logging.getLogger(__name__)

class WhoisEnricher:
    """Whois data enricher for IP ownership"""
    
    def __init__(self):
        self.cache_file = f'{DATA_FOLDER}/whois_cache.json'
        self.cache = {}
        self.load_cache()
    
    def load_cache(self):
        try:
            with open(self.cache_file, 'r') as f:
                self.cache = json.load(f)
            logger.info(f"Loaded {len(self.cache)} Whois cache entries")
        except:
            self.cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
            logger.info(f"Saved {len(self.cache)} Whois cache entries")
        except Exception as e:
            logger.error(f"Error saving Whois cache: {e}")
    
    def get_whois_data(self, ip):
        """Get Whois data for an IP"""
        # Check cache
        if ip in self.cache:
            return self.cache[ip]
        
        try:
            # Query Whois
            result = whois.whois(ip)
            
            if result:
                whois_data = {
                    'registrar': result.registrar if hasattr(result, 'registrar') else 'Unknown',
                    'creation_date': str(result.creation_date[0]) if hasattr(result, 'creation_date') and result.creation_date else 'Unknown',
                    'expiration_date': str(result.expiration_date[0]) if hasattr(result, 'expiration_date') and result.expiration_date else 'Unknown',
                    'updated_date': str(result.updated_date[0]) if hasattr(result, 'updated_date') and result.updated_date else 'Unknown',
                    'name_servers': result.name_servers if hasattr(result, 'name_servers') else [],
                    'org': result.org if hasattr(result, 'org') else 'Unknown',
                    'country': result.country if hasattr(result, 'country') else 'Unknown',
                    'emails': result.emails if hasattr(result, 'emails') else [],
                    'dnssec': result.dnssec if hasattr(result, 'dnssec') else 'Unknown'
                }
                
                # Cache the result
                self.cache[ip] = whois_data
                self.save_cache()
                
                return whois_data
            
        except Exception as e:
            logger.error(f"Error getting Whois data for {ip}: {e}")
        
        return None

# Singleton instance
_whois_enricher = None

def get_whois_enricher():
    global _whois_enricher
    if _whois_enricher is None:
        _whois_enricher = WhoisEnricher()
    return _whois_enricher