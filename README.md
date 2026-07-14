# 🛡️ Brute Force Detection & Threat Intelligence Dashboard

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](http://makeapullrequest.com)

A comprehensive **Threat Intelligence Dashboard** that analyzes SolarWinds CVE exports, detects brute force attacks, and provides real-time threat intelligence using VirusTotal, AbuseIPDB, and MITRE ATT&CK framework mapping.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Usage](#-usage)
- [Dashboard Overview](#-dashboard-overview)
- [API Endpoints](#-api-endpoints)
- [Project Structure](#-project-structure)
- [Screenshots](#-screenshots)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## 🚀 Features

### 🔍 Core Features
- **CSV Upload & Analysis** - Upload SolarWinds CVE exports for instant analysis
- **Brute Force Detection** - Identifies IPs with 5+ failed login attempts
- **Real-Time Monitoring** - WebSocket-powered live updates and alerts
- **IP Intelligence** - Enrich IPs with VirusTotal and AbuseIPDB scores
- **Geolocation Mapping** - Country, city, ISP, and coordinates for each IP

### 🎯 MITRE ATT&CK Integration
- Map detected threats to MITRE ATT&CK techniques
- Identify attack tactics and patterns
- View technique descriptions and IDs
- Correlate CVEs with MITRE framework

### 🛠️ Remediation & Response
- **Remediation Steps** - Immediate actions to mitigate threats
- **Blocking Commands** - OS-specific firewall commands (Windows/Linux/Mac)
- **Protection Measures** - Long-term security recommendations
- **Best Practices** - Security hardening guidelines
- **Copy to Clipboard** - One-click command copying

### 📊 Interactive Dashboard
- **Live Statistics** - Real-time attack metrics and KPI cards
- **Threat Distribution** - Visual charts for risk levels
- **Attack Timeline** - Chronological view of detected threats
- **Top Attackers** - Identify the most active malicious IPs
- **Multiple Color Themes** - 6 themes (Green, Purple, Red, Gold, Blue, Light)

### 📄 Export & Reporting
- **CSV Export** - Download IP reports in CSV format
- **JSON Export** - Export structured data for analysis
- **PDF Reports** - Generate professional security reports
- **Enriched IPs Export** - Download enriched threat intelligence data

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Flask (Python 3.11) |
| **Real-Time** | Flask-SocketIO, WebSockets |
| **Data Processing** | Pandas, NumPy |
| **Threat Intelligence** | VirusTotal API, AbuseIPDB API |
| **MITRE Mapping** | Custom MITRE ATT&CK framework mapper |
| **Frontend** | HTML5, CSS3, JavaScript |
| **Visualization** | Chart.js |
| **Styling** | Bootstrap 5, Custom CSS |
| **PDF Generation** | ReportLab |
| **Geolocation** | IP-API.com |
| **IP Analysis** | Python-Whois, GeoIP2 |

---

## 📦 Installation

### Prerequisites

- Python 3.11 or higher
- pip (Python package manager)
- Git (optional)

Step 1: Clone the Repository

```bash
git clone https://github.com/Aqib-shakeel07/Brute_Force_Detection.git
cd Brute_Force_Detection

Step 2: Create Virtual Environment (Recommended)
bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
Step 3: Install Dependencies
bash
pip install -r requirements.txt
Step 4: Configure Environment Variables
Create a .env file in the root directory:

env
# API Keys
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
SECRET_KEY=your_secret_key_here

# Enrichment Settings
ENABLE_API_ENRICHMENT=True
ENRICHMENT_TIMEOUT=300
MAX_IPS_TO_ENRICH=10

# Whois Settings (optional)
ENABLE_WHOIS=False

# Flask Settings
FLASK_DEBUG=True
HOST=0.0.0.0
PORT=5000
Step 5: Get API Keys
Service	Purpose	Sign Up Link
VirusTotal	IP reputation scoring	virustotal.com
AbuseIPDB	IP abuse reporting	abuseipdb.com
Shodan	Device information (optional)	shodan.io
Step 6: Run the Application
bash
python app.py
The dashboard will be available at: http://localhost:5000
🎯 Usage
Upload CSV File
Click on the upload zone or drag & drop your CSV file

Click "Analyze File" to start analysis

Watch real-time progress updates

View Threat Intelligence
Dashboard - See all detected threats and statistics

VirusTotal Page - Check IP reputation manually

AbuseIPDB Page - Check IP abuse reports

Remediate Threats
Click the "Remediate" button next to any suspicious IP

Review immediate remediation steps

Copy blocking commands to your clipboard

Implement protection measures

Export Reports
Click CSV, JSON, or PDF buttons

Download reports for documentation or sharing
