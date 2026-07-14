import os
import sys
import io
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

# Fix Windows console encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# ==================== ENRICHMENT SETTINGS ====================
ENABLE_API_ENRICHMENT = os.getenv('ENABLE_API_ENRICHMENT', 'True').lower() == 'true'  # Enabled by default
ENRICHMENT_TIMEOUT = int(os.getenv('ENRICHMENT_TIMEOUT', '300'))  # 5 minutes timeout
MAX_IPS_TO_ENRICH = int(os.getenv('MAX_IPS_TO_ENRICH', '10'))  # Only enrich top 10 IPs
ENABLE_WHOIS = os.getenv('ENABLE_WHOIS', 'False').lower() == 'true'  # Disabled by default


# ==================== API KEYS ====================
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '76b2bd59bc4189df1dbc61048e09de59fcbfd3de69b670ee1aa4ba94a39c7dc7')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '4216a37b64cd2d42af75b1b7c177d1cfd979dab0c269c9b5d9cfca9fae4e4516674365703cb310ee')
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', 'dev-secret-key-8f7e9a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7a8b9c')  # NEW

# ==================== API SETTINGS ====================
VT_API_URL = 'https://www.virustotal.com/api/v3'
ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2'

# API Rate Limits (Free tier)
VT_RATE_LIMIT_PER_MINUTE = 4  # VirusTotal free tier: 4 requests per minute
ABUSEIPDB_RATE_LIMIT_PER_DAY = 1000  # AbuseIPDB free tier: 1000 requests per day
API_TIMEOUT = 15  # Seconds to wait for API response

# ==================== CACHE SETTINGS ====================
CACHE_DURATION = timedelta(hours=24)  # How long to cache IP data
CACHE_FILE = 'data/ip_cache.json'

# ==================== DETECTION SETTINGS ====================
BRUTE_FORCE_THRESHOLD = 5  # Number of failed attempts to flag as suspicious
TIME_WINDOW = 300          # Time window in seconds (5 minutes)
BLOCK_DURATION = 3600      # Block duration in seconds (1 hour)

# ==================== CONFIDENCE SCORE WEIGHTS ====================
CONFIDENCE_WEIGHTS = {
    'attempts': 0.3,      # Weight for local brute force attempts
    'virustotal': 0.3,    # Weight for VirusTotal score
    'abuseipdb': 0.4      # Weight for AbuseIPDB score
}

# ==================== RISK LEVEL THRESHOLDS ====================
RISK_THRESHOLDS = {
    'critical': 80,   # 80-100 = Critical
    'high': 60,       # 60-79 = High
    'medium': 40,     # 40-59 = Medium
    'low': 0          # 0-39 = Low
}

# ==================== FILE PATHS ====================
UPLOAD_FOLDER = 'uploads'
DATA_FOLDER = 'data'
LOGS_FOLDER = 'logs'
STATIC_FOLDER = 'static'
TEMPLATES_FOLDER = 'templates'

# File paths for results
RESULTS_FILE = f'{DATA_FOLDER}/results.json'
SUMMARY_FILE = f'{DATA_FOLDER}/summary.json'
PUBLIC_REPORT_CSV = f'{DATA_FOLDER}/public_ips_report.csv'
PRIVATE_REPORT_CSV = f'{DATA_FOLDER}/private_ips_report.csv'
EXPORT_ALL_CSV = f'{DATA_FOLDER}/export_all.csv'
ENRICHED_IPS_FILE = f'{DATA_FOLDER}/enriched_ips.json'

ALLOWED_EXTENSIONS = {'txt', 'log', 'csv'}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB

# ==================== DASHBOARD SETTINGS ====================
DASHBOARD_TITLE = "Brute Force Detection & IP Intelligence Dashboard"
REFRESH_INTERVAL = 30  # Seconds
RESULTS_PER_PAGE = 50  # Pagination for results table

# ==================== LOGGING SETTINGS ====================
LOG_LEVEL = 'INFO'
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = f'{LOGS_FOLDER}/app.log'

# ==================== FLASK SETTINGS ====================
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
HOST = '0.0.0.0'
PORT = 5000

# ==================== CREATE DIRECTORIES ====================
for folder in [UPLOAD_FOLDER, DATA_FOLDER, LOGS_FOLDER, STATIC_FOLDER, TEMPLATES_FOLDER]:
    os.makedirs(folder, exist_ok=True)

# ==================== HELPER FUNCTION ====================
def get_config():
    """Return configuration as dictionary"""
    return {
        'virustotal_api_key': VIRUSTOTAL_API_KEY,
        'abuseipdb_api_key': ABUSEIPDB_API_KEY,
        'vt_api_url': VT_API_URL,
        'abuseipdb_api_url': ABUSEIPDB_API_URL,
        'vt_rate_limit': VT_RATE_LIMIT_PER_MINUTE,
        'abuseipdb_rate_limit': ABUSEIPDB_RATE_LIMIT_PER_DAY,
        'api_timeout': API_TIMEOUT,
        'cache_duration': CACHE_DURATION,
        'cache_file': CACHE_FILE,
        'brute_force_threshold': BRUTE_FORCE_THRESHOLD,
        'confidence_weights': CONFIDENCE_WEIGHTS,
        'risk_thresholds': RISK_THRESHOLDS,
        'upload_folder': UPLOAD_FOLDER,
        'data_folder': DATA_FOLDER,
        'logs_folder': LOGS_FOLDER,
        'allowed_extensions': ALLOWED_EXTENSIONS,
        'max_file_size': MAX_FILE_SIZE,
        'dashboard_title': DASHBOARD_TITLE,
        'refresh_interval': REFRESH_INTERVAL,
        'results_per_page': RESULTS_PER_PAGE,
        'log_file': LOG_FILE,
        'log_level': LOG_LEVEL,
        'secret_key': SECRET_KEY,
        'debug': DEBUG,
        'host': HOST,
        'port': PORT,
        'enable_api_enrichment': ENABLE_API_ENRICHMENT,
        'enrichment_timeout': ENRICHMENT_TIMEOUT,
        'max_ips_to_enrich': MAX_IPS_TO_ENRICH
    }

# ==================== PRINT CONFIGURATION STATUS ====================
print(f"✓ Configuration loaded successfully")
print(f"  - VirusTotal API Key: {'✅ Configured' if VIRUSTOTAL_API_KEY != 'your_virustotal_api_key_here' else '❌ Missing'}")
print(f"  - AbuseIPDB API Key: {'✅ Configured' if ABUSEIPDB_API_KEY != 'your_abuseipdb_api_key_here' else '❌ Missing'}")
print(f"  - API Enrichment: {'✅ Enabled' if ENABLE_API_ENRICHMENT else '❌ Disabled'}")
print(f"  - Max IPs to Enrich: {MAX_IPS_TO_ENRICH}")
print(f"  - Debug Mode: {DEBUG}")
print(f"  - Upload Folder: {UPLOAD_FOLDER}")
print(f"  - Data Folder: {DATA_FOLDER}")