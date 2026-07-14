from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
import os
import json
import logging
from datetime import datetime
import threading
import pandas as pd
from collections import defaultdict
import ipaddress
import time
import urllib3
from config import *
from ip_enricher import get_ip_enricher
from geo_enricher import get_geo_enricher
from whois_enricher import get_whois_enricher
from pdf_generator import get_pdf_generator
from remediation import get_remediation_engine
from config import ENABLE_WHOIS
from mitre_mapper import get_mitre_mapper

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app)

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Setup logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Store results in memory
analysis_results = {
    'all_ips': [],
    'public_ips': [],
    'private_ips': [],
    'enriched_ips': []
}

current_status = {
    'status': 'idle',
    'progress': 0,
    'total_ips': 0,
    'processed_ips': 0,
    'message': 'Ready to analyze',
    'total_rows': 0,
    'unique_ips': 0,
    'start_time': None,
    'end_time': None
}

analysis_summary = {
    'total_attempts': 0,
    'unique_ips': 0,
    'suspicious_ips': 0,
    'public_count': 0,
    'private_count': 0,
    'critical_count': 0,
    'high_count': 0,
    'medium_count': 0,
    'low_count': 0,
    'top_attacker': None,
    'most_targeted_user': None,
    'public_top_attacker': None,
    'private_top_attacker': None,
    'enriched_count': 0
}

# Track connected clients for real-time updates
connected_clients = set()

# ============================================================
# SOCKETIO EVENTS
# ============================================================

@socketio.on('connect')
def handle_connect():
    client_id = request.sid
    connected_clients.add(client_id)
    logger.info(f"Client connected: {client_id}")
    emit('connection_status', {'status': 'connected', 'message': 'Real-time monitoring active'})
    emit('status_update', current_status)
    if analysis_results.get('all_ips'):
        emit('results_update', analysis_results)

@socketio.on('disconnect')
def handle_disconnect():
    client_id = request.sid
    if client_id in connected_clients:
        connected_clients.remove(client_id)
    logger.info(f"Client disconnected: {client_id}")

@socketio.on('ping')
def handle_ping():
    emit('pong', {'timestamp': datetime.now().isoformat()})

def emit_realtime_update(event_type, data):
    if connected_clients:
        socketio.emit(event_type, {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'data': data
        })

def emit_attack_detected(ip, attempts, risk_level):
    emit_realtime_update('attack_detected', {
        'ip': ip,
        'attempts': attempts,
        'risk_level': risk_level,
        'timestamp': datetime.now().isoformat(),
        'message': f'🚨 Suspicious activity detected from {ip}'
    })

def emit_progress_update(progress, message):
    emit_realtime_update('progress_update', {
        'progress': progress,
        'message': message
    })

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def classify_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return 'private'
        elif ip_obj.is_loopback:
            return 'loopback'
        elif ip_obj.is_multicast:
            return 'multicast'
        elif ip_obj.is_reserved:
            return 'reserved'
        else:
            return 'public'
    except:
        return 'unknown'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    """Render main dashboard"""
    global analysis_results, analysis_summary
    return render_template('index.html', 
                         title=DASHBOARD_TITLE,
                         results=analysis_results,
                         summary=analysis_summary,
                         status=current_status,
                         active_page='home')

@app.route('/virustotal')
def virustotal_page():
    """VirusTotal Scanner page"""
    return render_template('virustotal.html', 
                         title='VirusTotal Scanner',
                         active_page='virustotal')

@app.route('/abuseipdb')
def abuseipdb_page():
    """AbuseIPDB Scanner page"""
    return render_template('abuseipdb.html', 
                         title='AbuseIPDB Scanner',
                         active_page='abuseipdb')

@app.route('/upload', methods=['POST'])
def upload_file():
    global analysis_results, current_status, analysis_summary
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed. Use .csv'}), 400
    
    try:
        filename = secure_filename(file.filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        current_status = {
            'status': 'processing',
            'progress': 0,
            'total_ips': 0,
            'processed_ips': 0,
            'message': 'Starting analysis...',
            'total_rows': 0,
            'unique_ips': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': None
        }
        
        emit_realtime_update('analysis_started', {'message': 'Analysis started'})
        emit_progress_update(0, 'Starting analysis...')
        
        analysis_summary = {
            'total_attempts': 0,
            'unique_ips': 0,
            'suspicious_ips': 0,
            'public_count': 0,
            'private_count': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'top_attacker': None,
            'most_targeted_user': None,
            'public_top_attacker': None,
            'private_top_attacker': None,
            'enriched_count': 0
        }
        
        analysis_results = {
            'all_ips': [],
            'public_ips': [],
            'private_ips': [],
            'enriched_ips': []
        }
        
        thread = threading.Thread(target=analyze_csv_file, args=(filepath,))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'message': 'File uploaded and analysis started',
            'filename': filename,
            'status_url': '/status'
        }), 202
        
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def analyze_csv_file(filepath):
    global analysis_results, current_status, analysis_summary
    
    try:
        emit_progress_update(0, 'Reading CSV file...')
        current_status['message'] = 'Reading CSV file...'
        
        try:
            df = pd.read_csv(filepath, encoding='utf-8')
        except:
            df = pd.read_csv(filepath, encoding='latin-1')
        
        current_status['total_rows'] = len(df)
        logger.info(f"Loaded CSV with {len(df)} rows")
        emit_progress_update(10, f'Loaded {len(df)} rows...')
        
        ip_column = None
        for col in df.columns:
            col_lower = col.lower()
            if 'source' in col_lower and ('ip' in col_lower or 'address' in col_lower or 'machine' in col_lower):
                ip_column = col
                break
            if col_lower in ['ip', 'sourceip', 'source_ip']:
                ip_column = col
                break
        
        if not ip_column:
            for col in df.columns:
                sample = df[col].dropna().astype(str).head(10)
                ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
                if sample.str.contains(ip_pattern, regex=True).any():
                    ip_column = col
                    break
        
        if not ip_column:
            logger.error("Could not find IP column in CSV")
            current_status['status'] = 'error'
            current_status['message'] = 'No IP column found in CSV'
            return
        
        username_column = None
        user_columns = ['DestinationAccount', 'Username', 'user', 'account', 'User', 
                       'TargetAccount', 'Account', 'DestinationAccount']
        for col in user_columns:
            if col in df.columns:
                username_column = col
                break
        
        time_column = None
        time_columns = ['DetectionTime', 'Time', 'timestamp', 'event_time', 'log_time']
        for col in time_columns:
            if col in df.columns:
                time_column = col
                break
        
        ip_counts = defaultdict(lambda: {'count': 0, 'usernames': set(), 'first_seen': None, 'last_seen': None})
        total_failures = 0
        user_counts = defaultdict(int)
        
        emit_progress_update(20, 'Analyzing login failures...')
        total_rows = len(df)
        
        for idx, row in df.iterrows():
            if idx % 100 == 0:
                progress = 20 + ((idx / total_rows) * 30)
                emit_progress_update(progress, f'Analyzing row {idx+1}/{total_rows}...')
            
            current_status['progress'] = 20 + ((idx / total_rows) * 30)
            current_status['processed_ips'] = idx + 1
            
            try:
                ip = str(row[ip_column]).strip()
                if ip == 'nan' or ip == '0.0.0.0' or not ip:
                    continue
                
                username = None
                if username_column and username_column in df.columns:
                    username = str(row[username_column]).strip()
                    if username == 'nan':
                        username = None
                
                timestamp = None
                if time_column and time_column in df.columns:
                    timestamp = str(row[time_column]).strip()
                    if timestamp == 'nan':
                        timestamp = None
                
                is_failure = True
                if 'EventType' in df.columns:
                    is_failure = 'Failure' in str(row.get('EventType', '')) or 'fail' in str(row.get('EventType', '')).lower()
                
                if is_failure:
                    total_failures += 1
                    ip_counts[ip]['count'] += 1
                    if username:
                        ip_counts[ip]['usernames'].add(username)
                        user_counts[username] += 1
                    if not ip_counts[ip]['first_seen']:
                        ip_counts[ip]['first_seen'] = timestamp
                    ip_counts[ip]['last_seen'] = timestamp
                    
            except Exception as e:
                logger.warning(f"Error processing row {idx}: {e}")
                continue
        
        emit_progress_update(50, 'Identifying brute force patterns...')
        current_status['message'] = 'Identifying brute force patterns...'
        
        suspicious_ips = []
        for ip, data in ip_counts.items():
            if data['count'] >= BRUTE_FORCE_THRESHOLD:
                suspicious_ips.append(ip)
        
        suspicious_ips.sort(key=lambda x: ip_counts[x]['count'], reverse=True)
        
        enriched_data = {}
        
        if ENABLE_API_ENRICHMENT and suspicious_ips:
            top_ips = suspicious_ips[:MAX_IPS_TO_ENRICH]
            logger.info(f"Enriching top {len(top_ips)} most malicious IPs")
            
            current_status['message'] = f'Enriching top {len(top_ips)} IPs...'
            emit_progress_update(60, f'Enriching top {len(top_ips)} IPs...')
            
            try:
                enricher = get_ip_enricher()
                enriched_data = enricher.enrich_ip_batch(top_ips, max_workers=2)
                emit_progress_update(70, f'Enriched {len(enriched_data)} IPs')
            except Exception as e:
                logger.error(f"Enrichment failed: {e}")
                enriched_data = {}
        
        emit_progress_update(75, 'Building results...')
        current_status['message'] = 'Building results...'
        
        all_brute_force = []
        public_brute_force = []
        private_brute_force = []
        enriched_ips_final = []
        
        geo_enricher = get_geo_enricher()
        whois_enricher = get_whois_enricher()
        
        # Initialize remediation engine
        remediation_engine = get_remediation_engine()
        
        # Initialize MITRE mapper
        mitre_mapper = get_mitre_mapper()
        
        for idx, (ip, data) in enumerate(ip_counts.items()):
            if data['count'] < BRUTE_FORCE_THRESHOLD:
                continue
            
            enrichment = enriched_data.get(ip, {})
            vt_data = enrichment.get('virustotal', {})
            abuse_data = enrichment.get('abuseipdb', {})
            
            ip_type = classify_ip(ip)
            
            geo_data = None
            whois_data = None
            
            # Only query for valid IPs (skip hostnames)
            if ip_type != 'unknown':
                try:
                    geo_data = geo_enricher.get_geolocation(ip)
                except Exception as e:
                    logger.error(f"Geo error for {ip}: {e}")
                
                # Only query Whois if enabled
                if ENABLE_WHOIS:
                    try:
                        whois_data = whois_enricher.get_whois_data(ip)
                    except Exception as e:
                        logger.error(f"Whois error for {ip}: {e}")
                else:
                    whois_data = None  # Skip Whois entirely
            
            # Detect attack pattern based on behavior
            attack_pattern = 'brute_force'
            if data['count'] > 100:
                attack_pattern = 'brute_force'
            elif data['count'] > 50:
                attack_pattern = 'credential_stuffing'
            elif len(data['usernames']) > 10:
                attack_pattern = 'password_spray'
            
            # Get MITRE mapping for attack pattern
            mitre_mapping = mitre_mapper.map_attack_pattern(attack_pattern)
            
            if ENABLE_API_ENRICHMENT and enrichment:
                try:
                    enricher = get_ip_enricher()
                    combined_score = enricher.get_combined_score({
                        'attempt_count': data['count'],
                        'virustotal': vt_data if vt_data else {},
                        'abuseipdb': abuse_data if abuse_data else {}
                    })
                    risk_level = enricher.get_risk_level(combined_score)
                except Exception as e:
                    combined_score = min(100, (data['count'] / 30) * 100)
                    if data['count'] > 100:
                        risk_level = 'CRITICAL'
                    elif data['count'] > 50:
                        risk_level = 'HIGH'
                    elif data['count'] > 20:
                        risk_level = 'MEDIUM'
                    else:
                        risk_level = 'LOW'
            else:
                combined_score = min(100, (data['count'] / 30) * 100)
                if data['count'] > 100:
                    risk_level = 'CRITICAL'
                elif data['count'] > 50:
                    risk_level = 'HIGH'
                elif data['count'] > 20:
                    risk_level = 'MEDIUM'
                else:
                    risk_level = 'LOW'
            
            vt_score = 0
            vt_malicious = 0
            abuse_score = 0
            abuse_reports = 0
            
            if ENABLE_API_ENRICHMENT and enrichment:
                if vt_data and isinstance(vt_data, dict):
                    vt_score = vt_data.get('score', 0)
                    vt_malicious = vt_data.get('malicious', 0)
                if abuse_data and isinstance(abuse_data, dict):
                    abuse_score = abuse_data.get('confidence_score', 0)
                    abuse_reports = abuse_data.get('total_reports', 0)
            
            # Build threat data for remediation
            threat_data = {
                'attempt_count': data['count'],
                'risk_level': risk_level,
                'virustotal_score': vt_score,
                'abuseipdb_score': abuse_score,
                'country': geo_data.get('country', 'Unknown') if geo_data else 'Unknown',
                'ip_type': ip_type
            }
            
            # Get remediation plan
            remediation_plan = remediation_engine.get_remediation_plan(ip, threat_data)
            
            ip_data = {
                'ip': ip,
                'attempt_count': data['count'],
                'usernames': list(data['usernames']),
                'unique_usernames': len(data['usernames']),
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'risk_level': risk_level,
                'confidence': combined_score,
                'ip_type': ip_type,
                'virustotal': vt_data if ENABLE_API_ENRICHMENT and enrichment else None,
                'abuseipdb': abuse_data if ENABLE_API_ENRICHMENT and enrichment else None,
                'virustotal_score': vt_score,
                'abuseipdb_score': abuse_score,
                'virustotal_malicious': vt_malicious,
                'abuseipdb_reports': abuse_reports,
                'is_enriched': bool(enrichment),
                'geolocation': geo_data,
                'whois': whois_data,
                'country': geo_data.get('country', 'Unknown') if geo_data else 'Unknown',
                'city': geo_data.get('city', 'Unknown') if geo_data else 'Unknown',
                'isp': geo_data.get('isp', 'Unknown') if geo_data else 'Unknown',
                'latitude': geo_data.get('latitude', 0) if geo_data else 0,
                'longitude': geo_data.get('longitude', 0) if geo_data else 0,
                'whois_registrar': whois_data.get('registrar', 'Unknown') if whois_data else 'Unknown',
                'whois_org': whois_data.get('org', 'Unknown') if whois_data else 'Unknown',
                # Remediation data
                'remediation_steps': remediation_plan.get('remediation_steps', []),
                'blocking_steps': remediation_plan.get('blocking_steps', []),
                'protection_steps': remediation_plan.get('protection_steps', []),
                'best_practices': remediation_plan.get('best_practices', []),
                'remediation_plan': remediation_plan,
                # MITRE ATT&CK data
                'mitre_mapping': mitre_mapping,
                'attack_pattern': attack_pattern,
                'mitre_technique': mitre_mapping.get('technique', 'T1110'),
                'mitre_tactic': mitre_mapping.get('tactic_name', 'Credential Access')
            }
            
            all_brute_force.append(ip_data)
            
            if ip_type == 'public':
                public_brute_force.append(ip_data)
            elif ip_type == 'private':
                private_brute_force.append(ip_data)
            
            if enrichment:
                enriched_ips_final.append(ip_data)
        
        all_brute_force.sort(key=lambda x: x['attempt_count'], reverse=True)
        public_brute_force.sort(key=lambda x: x['attempt_count'], reverse=True)
        private_brute_force.sort(key=lambda x: x['attempt_count'], reverse=True)
        enriched_ips_final.sort(key=lambda x: x['attempt_count'], reverse=True)
        
        global analysis_results
        analysis_results = {
            'all_ips': all_brute_force,
            'public_ips': public_brute_force,
            'private_ips': private_brute_force,
            'enriched_ips': enriched_ips_final
        }
        
        public_count = len(public_brute_force)
        private_count = len(private_brute_force)
        
        critical_count = sum(1 for ip in all_brute_force if ip['risk_level'] == 'CRITICAL')
        high_count = sum(1 for ip in all_brute_force if ip['risk_level'] == 'HIGH')
        medium_count = sum(1 for ip in all_brute_force if ip['risk_level'] == 'MEDIUM')
        low_count = sum(1 for ip in all_brute_force if ip['risk_level'] == 'LOW')
        
        top_attacker = all_brute_force[0] if all_brute_force else None
        public_top = public_brute_force[0] if public_brute_force else None
        private_top = private_brute_force[0] if private_brute_force else None
        
        most_targeted = max(user_counts.items(), key=lambda x: x[1]) if user_counts else None
        
        analysis_summary = {
            'total_attempts': total_failures,
            'unique_ips': len(ip_counts),
            'suspicious_ips': len(all_brute_force),
            'public_count': public_count,
            'private_count': private_count,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'top_attacker': top_attacker,
            'most_targeted_user': most_targeted[0] if most_targeted else None,
            'most_targeted_count': most_targeted[1] if most_targeted else 0,
            'public_top_attacker': public_top,
            'private_top_attacker': private_top,
            'enriched_count': len(enriched_ips_final)
        }
        
        os.makedirs(DATA_FOLDER, exist_ok=True)
        
        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(analysis_results, f, indent=2)
        
        with open(SUMMARY_FILE, 'w', encoding='utf-8') as f:
            json.dump(analysis_summary, f, indent=2)
        
        if enriched_ips_final:
            with open(ENRICHED_IPS_FILE, 'w', encoding='utf-8') as f:
                json.dump(enriched_ips_final, f, indent=2)
            pd.DataFrame(enriched_ips_final).to_csv(f'{DATA_FOLDER}/enriched_ips_report.csv', index=False)
        
        if public_brute_force:
            pd.DataFrame(public_brute_force).to_csv(PUBLIC_REPORT_CSV, index=False)
        
        if private_brute_force:
            pd.DataFrame(private_brute_force).to_csv(PRIVATE_REPORT_CSV, index=False)
        
        current_status['status'] = 'complete'
        current_status['progress'] = 100
        current_status['message'] = f'Analysis complete. Found {len(all_brute_force)} suspicious IPs ({public_count} public, {private_count} private). Enriched {len(enriched_ips_final)} top IPs.'
        current_status['total_ips'] = len(all_brute_force)
        current_status['end_time'] = datetime.now().isoformat()
        
        emit_progress_update(100, 'Analysis complete!')
        emit_realtime_update('analysis_complete', {
            'total_ips': len(all_brute_force),
            'message': f'✅ Analysis complete! Found {len(all_brute_force)} suspicious IPs'
        })
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        import traceback
        traceback.print_exc()
        current_status['status'] = 'error'
        current_status['message'] = f'Error during analysis: {str(e)}'
        emit_realtime_update('analysis_error', {'message': str(e)})

@app.route('/status')
def get_status():
    return jsonify(current_status)

@app.route('/results')
def get_results():
    return jsonify(analysis_results)

@app.route('/summary')
def get_summary():
    return jsonify(analysis_summary)

# ============================================================
# API ENDPOINTS FOR VIRUSTOTAL SCANNER
# ============================================================

@app.route('/api/virustotal/check', methods=['POST'])
def check_virustotal():
    """Check IP against VirusTotal API"""
    try:
        data = request.json
        ip = data.get('ip', '').strip()
        
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        try:
            ipaddress.ip_address(ip)
        except:
            return jsonify({'error': 'Invalid IP address'}), 400
        
        from ip_enricher import get_ip_enricher
        enricher = get_ip_enricher()
        vt_data = enricher.get_virustotal_score(ip)
        
        if vt_data:
            return jsonify({
                'success': True,
                'ip': ip,
                'data': vt_data,
                'source': 'VirusTotal'
            })
        else:
            return jsonify({
                'success': False,
                'ip': ip,
                'error': 'No data available for this IP',
                'source': 'VirusTotal'
            }), 404
            
    except Exception as e:
        logger.error(f"VirusTotal API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/abuseipdb/check', methods=['POST'])
def check_abuseipdb():
    """Check IP against AbuseIPDB API"""
    try:
        data = request.json
        ip = data.get('ip', '').strip()
        
        if not ip:
            return jsonify({'error': 'IP address required'}), 400
        
        try:
            ipaddress.ip_address(ip)
        except:
            return jsonify({'error': 'Invalid IP address'}), 400
        
        from ip_enricher import get_ip_enricher
        enricher = get_ip_enricher()
        abuse_data = enricher.get_abuseipdb_score(ip)
        
        if abuse_data:
            return jsonify({
                'success': True,
                'ip': ip,
                'data': abuse_data,
                'source': 'AbuseIPDB'
            })
        else:
            return jsonify({
                'success': False,
                'ip': ip,
                'error': 'No data available for this IP',
                'source': 'AbuseIPDB'
            }), 404
            
    except Exception as e:
        logger.error(f"AbuseIPDB API error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================
# REMEDIATION API ENDPOINT
# ============================================================

@app.route('/api/remediation/<ip>')
def get_remediation(ip):
    """Get remediation steps for a specific IP"""
    try:
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except:
            return jsonify({'error': 'Invalid IP address'}), 400
        
        # Find the IP in results
        ip_data = None
        for result in analysis_results.get('all_ips', []):
            if result.get('ip') == ip:
                ip_data = result
                break
        
        if not ip_data:
            return jsonify({'error': 'IP not found in analysis results'}), 404
        
        # Prepare threat data
        threat_data = {
            'attempt_count': ip_data.get('attempt_count', 0),
            'risk_level': ip_data.get('risk_level', 'MEDIUM'),
            'virustotal_score': ip_data.get('virustotal_score', 0),
            'abuseipdb_score': ip_data.get('abuseipdb_score', 0),
            'country': ip_data.get('country', 'Unknown'),
            'ip_type': ip_data.get('ip_type', 'public')
        }
        
        # Get remediation plan
        engine = get_remediation_engine()
        remediation_plan = engine.get_remediation_plan(ip, threat_data)
        
        # Add MITRE mapping to response
        mitre_mapper = get_mitre_mapper()
        mitre_mapping = mitre_mapper.map_attack_pattern(ip_data.get('attack_pattern', 'brute_force'))
        
        remediation_plan['mitre_mapping'] = mitre_mapping
        remediation_plan['attack_pattern'] = ip_data.get('attack_pattern', 'brute_force')
        
        return jsonify(remediation_plan)
        
    except Exception as e:
        logger.error(f"Remediation error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================
# MITRE ATT&CK ENDPOINTS
# ============================================================

@app.route('/api/mitre/cve/<cve_id>')
def get_cve_mitre_mapping(cve_id):
    """Get MITRE ATT&CK mapping for a CVE"""
    try:
        mapper = get_mitre_mapper()
        mapping = mapper.map_cve(cve_id)
        return jsonify({
            'success': True,
            'cve': cve_id,
            'mapping': mapping
        })
    except Exception as e:
        logger.error(f"MITRE mapping error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mitre/attack-pattern/<pattern>')
def get_attack_pattern_mapping(pattern):
    """Get MITRE ATT&CK mapping for an attack pattern"""
    try:
        mapper = get_mitre_mapper()
        mapping = mapper.map_attack_pattern(pattern)
        return jsonify({
            'success': True,
            'pattern': pattern,
            'mapping': mapping
        })
    except Exception as e:
        logger.error(f"MITRE mapping error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mitre/summary')
def get_mitre_summary():
    """Get MITRE ATT&CK summary for all detected threats"""
    global analysis_results
    
    try:
        mapper = get_mitre_mapper()
        
        # Extract attack patterns from results
        attack_patterns = []
        for ip in analysis_results.get('all_ips', []):
            if ip.get('attack_pattern'):
                attack_patterns.append(ip.get('attack_pattern'))
        
        # Get MITRE mapping for each pattern
        patterns_summary = {}
        for pattern in set(attack_patterns):
            mapping = mapper.map_attack_pattern(pattern)
            if mapping:
                patterns_summary[pattern] = mapping
        
        return jsonify({
            'success': True,
            'patterns': patterns_summary,
            'total_ips': len(analysis_results.get('all_ips', [])),
            'unique_patterns': len(patterns_summary)
        })
    except Exception as e:
        logger.error(f"MITRE summary error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/mitre/matrix')
def get_mitre_matrix():
    """Get full MITRE ATT&CK matrix"""
    try:
        mapper = get_mitre_mapper()
        matrix = mapper.get_mitre_matrix()
        return jsonify({
            'success': True,
            'matrix': matrix
        })
    except Exception as e:
        logger.error(f"MITRE matrix error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================
# FILTER, SEARCH, PAGINATION ENDPOINTS
# ============================================================

@app.route('/filter', methods=['POST'])
def filter_results():
    global analysis_results
    try:
        data = request.json
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        if not start_date or not end_date:
            return jsonify({'error': 'Start and end dates required'}), 400
        
        start = datetime.fromisoformat(start_date)
        end = datetime.fromisoformat(end_date)
        
        filtered_all = []
        filtered_public = []
        filtered_private = []
        
        for ip in analysis_results.get('all_ips', []):
            if ip.get('first_seen'):
                try:
                    ip_date = datetime.fromisoformat(ip['first_seen'])
                    if start <= ip_date <= end:
                        filtered_all.append(ip)
                        if ip.get('ip_type') == 'public':
                            filtered_public.append(ip)
                        elif ip.get('ip_type') == 'private':
                            filtered_private.append(ip)
                except:
                    pass
        
        return jsonify({
            'all_ips': filtered_all,
            'public_ips': filtered_public,
            'private_ips': filtered_private
        })
        
    except Exception as e:
        logger.error(f"Filter error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/search', methods=['GET'])
def search_ips():
    global analysis_results
    query = request.args.get('q', '').strip()
    
    if not query:
        return jsonify({'error': 'Search query required'}), 400
    
    results = []
    for ip in analysis_results.get('all_ips', []):
        if query.lower() in ip.get('ip', '').lower():
            results.append(ip)
        for username in ip.get('usernames', []):
            if query.lower() in username.lower():
                if ip not in results:
                    results.append(ip)
    
    return jsonify(results)

@app.route('/results/paginated', methods=['GET'])
def get_paginated_results():
    global analysis_results
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        ip_type = request.args.get('type', 'all')
        
        if ip_type == 'public':
            data = analysis_results.get('public_ips', [])
        elif ip_type == 'private':
            data = analysis_results.get('private_ips', [])
        else:
            data = analysis_results.get('all_ips', [])
        
        total = len(data)
        start = (page - 1) * per_page
        end = start + per_page
        paginated_data = data[start:end]
        
        return jsonify({
            'data': paginated_data,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        })
        
    except Exception as e:
        logger.error(f"Pagination error: {e}")
        return jsonify({'error': str(e)}), 500

# ============================================================
# EXPORT ENDPOINTS
# ============================================================

@app.route('/export/csv/all')
def export_csv_all():
    if not analysis_results.get('all_ips'):
        return jsonify({'error': 'No results to export'}), 404
    
    df = pd.DataFrame(analysis_results['all_ips'])
    os.makedirs(DATA_FOLDER, exist_ok=True)
    csv_path = f"{DATA_FOLDER}/export_all_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True)

@app.route('/export/csv/public')
def export_csv_public():
    if not analysis_results.get('public_ips'):
        return jsonify({'error': 'No public IP results to export'}), 404
    
    df = pd.DataFrame(analysis_results['public_ips'])
    os.makedirs(DATA_FOLDER, exist_ok=True)
    csv_path = f"{DATA_FOLDER}/export_public_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True)

@app.route('/export/csv/private')
def export_csv_private():
    if not analysis_results.get('private_ips'):
        return jsonify({'error': 'No private IP results to export'}), 404
    
    df = pd.DataFrame(analysis_results['private_ips'])
    os.makedirs(DATA_FOLDER, exist_ok=True)
    csv_path = f"{DATA_FOLDER}/export_private_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True)

@app.route('/export/csv/enriched')
def export_csv_enriched():
    if not analysis_results.get('enriched_ips'):
        return jsonify({'error': 'No enriched IP results to export'}), 404
    
    df = pd.DataFrame(analysis_results['enriched_ips'])
    os.makedirs(DATA_FOLDER, exist_ok=True)
    csv_path = f"{DATA_FOLDER}/export_enriched_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    df.to_csv(csv_path, index=False)
    return send_file(csv_path, as_attachment=True)

@app.route('/export/json/all')
def export_json_all():
    if not analysis_results.get('all_ips'):
        return jsonify({'error': 'No results to export'}), 404
    
    json_path = f"{DATA_FOLDER}/export_all_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({
            'summary': analysis_summary,
            'results': analysis_results['all_ips']
        }, f, indent=2)
    return send_file(json_path, as_attachment=True)

@app.route('/export/json/enriched')
def export_json_enriched():
    if not analysis_results.get('enriched_ips'):
        return jsonify({'error': 'No enriched IP results to export'}), 404
    
    json_path = f"{DATA_FOLDER}/export_enriched_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({
            'summary': analysis_summary,
            'enriched_results': analysis_results['enriched_ips']
        }, f, indent=2)
    return send_file(json_path, as_attachment=True)

@app.route('/export/pdf')
def export_pdf():
    global analysis_results, analysis_summary
    
    if not analysis_results.get('all_ips'):
        return jsonify({'error': 'No results to export'}), 404
    
    try:
        pdf_gen = get_pdf_generator()
        filename = f"{DATA_FOLDER}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        success = pdf_gen.generate_report(analysis_results, analysis_summary, filename, is_enriched=False)
        
        if success:
            return send_file(filename, as_attachment=True)
        else:
            return jsonify({'error': 'Failed to generate PDF'}), 500
            
    except Exception as e:
        logger.error(f"PDF export error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/export/pdf/enriched')
def export_pdf_enriched():
    global analysis_results, analysis_summary
    
    if not analysis_results.get('enriched_ips'):
        return jsonify({'error': 'No enriched IP results to export'}), 404
    
    try:
        pdf_gen = get_pdf_generator()
        filename = f"{DATA_FOLDER}/enriched_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        enriched_data = {
            'all_ips': analysis_results['enriched_ips'],
            'public_ips': [],
            'private_ips': [],
            'enriched_ips': analysis_results['enriched_ips']
        }
        
        success = pdf_gen.generate_report(enriched_data, analysis_summary, filename, is_enriched=True)
        
        if success:
            return send_file(filename, as_attachment=True)
        else:
            return jsonify({'error': 'Failed to generate PDF'}), 500
            
    except Exception as e:
        logger.error(f"PDF enriched export error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/clear', methods=['POST'])
def clear_results():
    global analysis_results, current_status, analysis_summary
    
    analysis_results = {
        'all_ips': [],
        'public_ips': [],
        'private_ips': [],
        'enriched_ips': []
    }
    
    current_status = {
        'status': 'idle',
        'progress': 0,
        'total_ips': 0,
        'processed_ips': 0,
        'message': 'Cleared',
        'total_rows': 0,
        'unique_ips': 0,
        'start_time': None,
        'end_time': None
    }
    
    analysis_summary = {
        'total_attempts': 0,
        'unique_ips': 0,
        'suspicious_ips': 0,
        'public_count': 0,
        'private_count': 0,
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'low_count': 0,
        'top_attacker': None,
        'most_targeted_user': None,
        'public_top_attacker': None,
        'private_top_attacker': None,
        'enriched_count': 0
    }
    
    for file in [RESULTS_FILE, SUMMARY_FILE, PUBLIC_REPORT_CSV, PRIVATE_REPORT_CSV, ENRICHED_IPS_FILE]:
        if os.path.exists(file):
            os.remove(file)
    
    return jsonify({'message': 'Results cleared'})

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(LOGS_FOLDER, exist_ok=True)
    os.makedirs(DATA_FOLDER, exist_ok=True)
    os.makedirs(TEMPLATES_FOLDER, exist_ok=True)
    socketio.run(app, debug=DEBUG, host=HOST, port=PORT)