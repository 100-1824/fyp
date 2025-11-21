# DIDS Codebase Architecture Analysis

## Project Overview
DIDS (Distributed Intrusion Detection System) is a comprehensive network security monitoring platform with multiple detection layers, threat intelligence integration, and machine learning capabilities.

## 1. Project Structure

### Directory Organization
```
/home/user/fyp/
├── dids-dashboard/           # Main application (Flask backend + HTML frontend)
│   ├── api/                  # REST API routes
│   │   ├── dashboard.py      # Main API with 970 lines (threat intel, threats, stats)
│   │   └── rules.py          # Rules management API
│   ├── routes/               # Flask route blueprints
│   │   ├── api.py            # API endpoints (stats, threats, AI detection)
│   │   ├── auth.py           # Authentication routes
│   │   ├── main.py           # Main page routes
│   │   └── admin.py          # Admin routes
│   ├── services/             # Business logic services
│   │   ├── packet_capture.py       # Packet capture and processing
│   │   ├── threat_detection.py     # Signature-based detection
│   │   ├── ai_detection.py         # ML-based detection
│   │   ├── threat_intelligence.py  # Threat intel integration
│   │   ├── rl_detection.py         # Reinforcement learning
│   │   └── rule_engine.py          # Rule processing
│   ├── templates/            # Frontend HTML pages
│   │   ├── threat_intel.html # Threat Intelligence page
│   │   ├── threats.html      # Threats/Detections page
│   │   ├── ai_detection.html # AI Detection page
│   │   ├── analytics.html    # Analytics/Reports page
│   │   ├── index.html        # Dashboard home
│   │   └── ...
│   ├── model/                # ML models and supporting files
│   │   ├── dids_final.keras  # Main neural network model
│   │   ├── feature_names.json# Feature list
│   │   ├── scaler.pkl        # Feature scaler
│   │   └── label_encoder.pkl # Attack type encoder
│   ├── static/js/            # Client-side JavaScript
│   │   └── interactive-utils.js
│   ├── database/             # Database models/migrations
│   ├── app.py                # Flask app factory
│   ├── config.py             # Configuration management
│   └── requirements.txt       # Python dependencies
│
├── microservices/            # Distributed microservices
│   ├── api-gateway/          # Service orchestrator (port 5000)
│   │   └── app.py            # Routing to other services
│   ├── threat-intel/         # Threat Intelligence service (port 5005)
│   │   └── app.py            # IBM X-Force & OTX integration
│   ├── ai-detection/         # AI Detection microservice (port 5003)
│   │   └── app.py            # ML threat detection
│   ├── signature-detection/  # Pattern-based detection (port 5002)
│   │   └── app.py            # Suricata/Snort integration
│   ├── traffic-capture/      # Packet capture service (port 5001)
│   │   └── app.py            # Network traffic collection
│   ├── rl-detection/         # Reinforcement learning (port 5004)
│   │   └── app.py            # RL-based decisions
│   └── shared/               # Shared code
│       └── config.py         # Configuration management
│
├── docker-compose.yml        # Container orchestration
├── rl_module/                # RL training module
├── anomaly-detection/        # Anomaly detection service
├── ml-training/              # ML model training
└── terraform/                # Infrastructure as Code
```

## 2. Frontend to Backend Data Flow

### 2.1 Threat Intelligence Page
**File**: `/home/user/fyp/dids-dashboard/templates/threat_intel.html`

**API Endpoints Called**:
- `GET /api/v1/threat-intel/statistics` - Get TI service stats
- `GET /api/v1/threat-intel/pulses?limit=10` - Fetch OTX threat pulses
- `GET /api/v1/threat-intel/indicators` - Get cached malicious indicators
- `GET /api/v1/threat-intel/lookup/ip/<ip>` - IP reputation lookup
- `POST /api/v1/threat-intel/lookup/url` - URL analysis
- `GET /api/v1/threat-intel/lookup/domain/<domain>` - Domain reputation
- `GET /api/v1/threat-intel/lookup/hash/<hash>` - File hash analysis

**Backend Handler**: `/home/user/fyp/dids-dashboard/api/dashboard.py` (lines 463-700)

**Issues**:
- "Failed to load pulses" - Returns `{"error": "OTX API not configured"}` if `OTX_API_KEY` is not set
- "Failed to load indicators" - Shows empty indicator lists if threat-intel service returns error
- IBM X-Force showing "Checking..." - Missing `XFORCE_API_KEY` and `XFORCE_API_PASSWORD`
- AlienVault OTX showing "Checking..." - Missing `OTX_API_KEY`

---

### 2.2 Threats Page
**File**: `/home/user/fyp/dids-dashboard/templates/threats.html`

**API Endpoint Called**:
- `GET /api/combined-threats` - Gets both signature and AI detections

**Backend Handler**: `/home/user/fyp/dids-dashboard/routes/api.py` (lines 102-124)

**Data Sources**:
1. Signature-based threats from `threat_service.get_recent_threats()`
2. AI-based threats from `ai_service.get_recent_detections()`

**Issue - All Zeros**:
- No packets are being captured (packet_service not collecting data)
- No threats detected (threat_service has empty detections list)
- AI service might not be ready or not receiving data

---

### 2.3 AI Detection Page
**File**: `/home/user/fyp/dids-dashboard/templates/ai_detection.html`

**API Endpoints Called**:
- `GET /api/ai-stats` - Get detection statistics
- `GET /api/ai-model-info` - Get model metadata
- `GET /api/ai-detections` - Get recent AI detections
- `POST /api/ai-threshold` - Set confidence threshold

**Backend Handler**: `/home/user/fyp/dids-dashboard/routes/api.py` (lines 69-100)

**Model Loading Path**:
1. AI service checks for model file at: `/app/model/dids_final.keras`
2. Requires supporting files: `scaler.pkl`, `label_encoder.pkl`, `feature_names.json`
3. Located at: `/home/user/fyp/dids-dashboard/model/`

**Issue - 0 Detections**:
- Model not loaded (file not mounted in container or not found)
- No packets being processed through the AI detection pipeline
- AI service not initialized or model loading failed

---

### 2.4 Analytics Page
**File**: `/home/user/fyp/dids-dashboard/templates/analytics.html`

**API Endpoints Called**:
- `GET /api/stats` - Network statistics
- `GET /api/ai-stats` - AI detection statistics
- `GET /api/combined-threats` - All threats

**Data Dependencies**:
- Packet count (from packet_service)
- AI detections (from ai_service)
- Signature-based threats (from threat_service)

**Issue - 0 Threats with Packets**:
- Packets are being captured but not being analyzed
- Detection services not processing the captured traffic

---

## 3. Configuration Files & Environment Variables

### 3.1 Main Configuration
**File**: `/home/user/fyp/dids-dashboard/config.py`

**Critical Configuration Parameters**:
```python
# Database
MONGO_URI = "mongodb://localhost:27017/dids_dashboard"

# Microservice URLs
API_GATEWAY_URL = "http://localhost:5000"
TRAFFIC_CAPTURE_URL = "http://localhost:5001"
SIGNATURE_DETECTION_URL = "http://localhost:5002"
AI_DETECTION_URL = "http://localhost:5003"
RL_DETECTION_URL = "http://localhost:5004"
THREAT_INTEL_URL = "http://localhost:5005"

# Threat Intelligence APIs
XFORCE_API_KEY = ""              # IBM X-Force API Key (MISSING!)
XFORCE_API_PASSWORD = ""         # IBM X-Force Password (MISSING!)
OTX_API_KEY = ""                 # AlienVault OTX Key (MISSING!)

# Network Capture
DEFAULT_INTERFACE = "eth0"       # Network interface for packet capture
TRAFFIC_DATA_MAX_SIZE = 1000
THREAT_DETECTION_BUFFER = 20

# Caching
THREAT_INTEL_CACHE_TTL = 3600
THREAT_INTEL_ENABLED = True
```

### 3.2 Docker Environment Variables (docker-compose.yml)
```yaml
threat-intel:
  environment:
    XFORCE_API_KEY: ${XFORCE_API_KEY:-}        # EMPTY!
    XFORCE_API_PASSWORD: ${XFORCE_API_PASSWORD:-}  # EMPTY!
    OTX_API_KEY: ${OTX_API_KEY:-}               # EMPTY!
    THREAT_INTEL_PORT: 5005
    LOG_LEVEL: INFO
```

---

## 4. Backend Services Architecture

### 4.1 API Gateway (Port 5000)
**Role**: Main orchestrator routing requests to other microservices

**Endpoints**:
- `GET /health` - Check all service health
- `POST /analyze/packet` - Analyze packet through all detection layers
- `GET /statistics` - Aggregate service statistics
- `GET /traffic/recent` - Recent traffic data
- `GET /detections/recent` - Recent threat detections

**Implementation**: `/home/user/fyp/microservices/api-gateway/app.py`

---

### 4.2 Threat Intelligence Service (Port 5005)
**Role**: Threat intelligence lookups and caching

**API Endpoints**:
```
GET  /health                      # Service health
GET  /lookup/ip/<ip>             # IP reputation (X-Force + OTX)
POST /lookup/url                 # URL analysis
GET  /lookup/domain/<domain>     # Domain reputation
GET  /lookup/hash/<hash>         # Malware hash lookup
POST /lookup/bulk/ips            # Bulk IP lookups
GET  /pulses                     # OTX threat pulses (REQUIRES OTX_API_KEY!)
GET  /indicators                 # Cached malicious indicators
POST /indicators/import          # Import indicators
GET  /statistics                 # Service statistics
GET  /cache/clear                # Clear cache
```

**Configuration**:
- **IBM X-Force**: Requires `XFORCE_API_KEY` and `XFORCE_API_PASSWORD`
- **AlienVault OTX**: Requires `OTX_API_KEY`
- Both APIs are optional - service falls back gracefully

**Implementation**: `/home/user/fyp/microservices/threat-intel/app.py`

**Issue**: Without API keys configured, `/pulses` endpoint returns 503 error

---

### 4.3 AI Detection Service (Port 5003)
**Role**: Machine learning-based threat detection

**API Endpoints**:
```
GET  /health          # Service health (includes model_loaded status)
POST /detect          # Detect threat in packet data
GET  /model/info      # Model metadata and classes
GET  /statistics      # Detection statistics
```

**Model Requirements**:
- **Location**: `/app/model/` (mounted volume in Docker)
- **Files**:
  - `dids_final.keras` - Main neural network model
  - `scaler.pkl` - Feature scaling object
  - `label_encoder.pkl` - Attack type encoder
  - `feature_names.json` - List of expected features

**Features Extracted from Packets**:
- protocol, packet_length, src_port, dst_port
- TCP flags: syn, ack, psh, rst, fin
- Padded to 77 features total

**Attack Types Detected**:
- DDoS, Bot, PortScan, Web Attack, Brute Force, Infiltration, Benign

**Implementation**: `/home/user/fyp/microservices/ai-detection/app.py`

**Issue**: Model files not properly mounted or model loading fails at startup

---

### 4.4 Signature Detection Service (Port 5002)
**Role**: Pattern-based threat detection (Suricata/Snort compatible)

**Signatures Implemented**:
- ET MALWARE Reverse Shell (ports 4444, 5555, 6666, 7777, 31337)
- ET SCAN Aggressive Port Scan
- ET WEB SQL Injection Attempt
- ET WEB XSS Attack
- ET DNS Excessive Queries

**Payload Patterns**:
- SQL injection: `UNION SELECT`, `OR 1=1`, `DROP TABLE`
- XSS: `<script>`, `javascript:`, `onerror=`, `onload=`
- Command injection: `rm -rf`, `nc`, `/bin/bash`, `wget`

**Implementation**: `/home/user/fyp/microservices/signature-detection/app.py`

---

### 4.5 Traffic Capture Service (Port 5001)
**Role**: Network packet capture and initial processing

**Network Requirements**:
- Host networking mode required
- Privileged mode required
- NET_ADMIN and NET_RAW capabilities needed
- Interface to listen on: configurable (default: eth0)

**Implementation**: Live packet capture using pcap library

---

## 5. Service Dependencies & Communication

### Service URLs (configured in config.py)
```
Dashboard → API Gateway (5000)
  ├→ Threat Intelligence Service (5005)
  ├→ AI Detection Service (5003)
  ├→ Signature Detection Service (5002)
  ├→ Traffic Capture Service (5001)
  └→ RL Detection Service (5004)
```

### Database Stack
- **PostgreSQL**: User management, alerts, persistence
- **MongoDB**: DIDS data storage, threat detection logs
- **Redis**: Caching, session management
- **RabbitMQ**: Message queue for async operations

---

## 6. Root Cause Analysis: Why Features Aren't Working

### Issue 1: "Failed to load pulses" & "Failed to load indicators"
**Cause**: 
- `OTX_API_KEY` not set in environment or config
- Threat Intelligence service returns 503 error when API key is missing

**Location of Check**:
`/home/user/fyp/microservices/threat-intel/app.py`, lines 675-676:
```python
if not OTX_API_KEY:
    return jsonify({"error": "OTX API not configured"}), 503
```

**Fix Required**:
- Set `OTX_API_KEY` environment variable
- Or set `XFORCE_API_KEY` and `XFORCE_API_PASSWORD` for X-Force

---

### Issue 2: IBM X-Force and AlienVault OTX showing "Checking..."
**Cause**:
- Frontend expects data but services are unavailable
- Endpoints return 503 (Service Unavailable) due to missing credentials

**Configuration Check** (`/home/user/fyp/microservices/threat-intel/app.py`, lines 104-106):
```python
if not XFORCE_API_KEY or not XFORCE_API_PASSWORD:
    logger.debug("X-Force API not configured, skipping request")
    return None
```

---

### Issue 3: Threats page showing all zeros
**Cause**:
- Packet capture service not collecting traffic
  OR
- Threat detection services not receiving captured packets
  OR
- No actual threats in captured traffic

**Data Flow Problem**:
1. PacketCaptureService needs to be running and collecting packets
2. Packets must be processed through ThreatDetectionService
3. Results stored in threat_service.detections list
4. API endpoint `/api/combined-threats` returns this data

**Check Points**:
- Is network interface correctly configured? (`DEFAULT_INTERFACE = "eth0"`)
- Is packet capture started in `app.py`? (Line 175-185)
- Are there actual threats in the traffic?

---

### Issue 4: AI Detection showing 0 detections
**Cause**:
- AI model files not properly mounted in Docker
  OR
- Model loading failed at service startup
  OR
- No packets being routed to AI detection service

**Model Loading Flow**:
1. AI Detection Service starts (port 5003)
2. Loads `dids_final.keras` from `/app/model/`
3. Loads supporting files (scaler, encoder, features)
4. Sets `model_loaded = True` only if all files found
5. `/health` endpoint returns `{"model_loaded": false}` if failed

**Check Point in Code** (`/home/user/fyp/microservices/ai-detection/app.py`, lines 48-94):
```python
model_path = Path("/app/model")  # Must be mounted as Docker volume!
model_file = model_file / "dids_final.keras"
```

**Docker Mount Configuration** (`docker-compose.yml`, line 135):
```yaml
anomaly-detection:
  volumes:
    - ./dids-dashboard/model:/models:ro
```

**Issue**: Volume path might be wrong or model files missing!

---

### Issue 5: Analytics showing 0 threats despite having packets
**Cause**:
- Packets captured but not analyzed
- Detection services not processing captured data
- Services might not be running or communicating

**Verification Steps**:
1. Check API Gateway health: `GET http://localhost:5000/health`
2. Check individual service health endpoints
3. Verify packet capture is active: `GET /api/capture/status`
4. Check if threats are being detected: `GET /api/threats`
5. Check API call logs for errors

---

## 7. Key Configuration Requirements

### For Running Locally (Development)
```bash
# Create .env file or set environment variables
export FLASK_ENV=development
export FLASK_HOST=0.0.0.0
export FLASK_PORT=8000
export MONGO_URI=mongodb://localhost:27017/dids_dashboard
export DEFAULT_INTERFACE=eth0
export LOG_LEVEL=INFO

# Threat Intelligence (OPTIONAL but needed for TI page)
export XFORCE_API_KEY=your_key
export XFORCE_API_PASSWORD=your_password
export OTX_API_KEY=your_key
```

### For Docker Deployment
```bash
# .env file for docker-compose
POSTGRES_PASSWORD=changeme
RABBITMQ_PASSWORD=changeme
GRAFANA_PASSWORD=admin

# Threat Intelligence Credentials (CRITICAL)
XFORCE_API_KEY=your_key
XFORCE_API_PASSWORD=your_password
OTX_API_KEY=your_key

# Optional
CAPTURE_INTERFACE=eth0
RL_FAILSAFE=true
```

### Network Interface Configuration
- **Default**: `eth0`
- **Docker**: Often `eth0` or `veth*`
- **Kubernetes**: Interface name depends on CNI plugin
- **Check available**: `ip link show` or `ifconfig`

---

## 8. Services That Must Be Running

### Required for Core Functionality
1. **dids-dashboard** (Flask app) - Port 8000
   - Provides web UI and main API
   - Loads models and services on startup

2. **API Gateway** - Port 5000
   - Orchestrates other services
   - Required for `/analyze/packet` endpoints

3. **Threat Detection Service** - Port 5002
   - Pattern-based detection
   - Can work standalone

4. **Traffic Capture Service** - Port 5001
   - Collects network packets
   - Requires root/privileged mode and specific network interface

5. **AI Detection Service** - Port 5003
   - ML-based detection
   - Requires model files mounted at `/app/model/`

### Required for Threat Intelligence
- **Threat Intelligence Service** - Port 5005
  - Works without API keys (returns empty results)
  - Requires API keys for X-Force and OTX features

### Required for Full Features
- **PostgreSQL** - Database
- **MongoDB** - Data storage
- **Redis** - Caching
- **RabbitMQ** - Message queue

---

## 9. Debugging Checklist

### Check Service Health
```bash
# API Gateway
curl http://localhost:5000/health

# AI Detection
curl http://localhost:5003/health

# Threat Intelligence
curl http://localhost:5005/health

# Dashboard
curl http://localhost:8000/api/v1/threat-intel/statistics
```

### Check Packet Capture
```bash
# Is capture running?
curl http://localhost:8000/api/capture/status

# Get recent threats
curl http://localhost:8000/api/threats
curl http://localhost:8000/api/combined-threats

# Get stats
curl http://localhost:8000/api/stats
curl http://localhost:8000/api/ai-stats
```

### Check Configuration
```bash
# Verify environment variables are set
printenv | grep -E "XFORCE|OTX|MONGO|INTERFACE"

# Check if files exist
ls -la /home/user/fyp/dids-dashboard/model/

# Verify network interface
ip link show
```

---

## 10. Summary Table

| Feature | Status | Root Cause | Required Component |
|---------|--------|------------|-------------------|
| Threat Intelligence Lookups | Partial | Missing API Keys | OTX_API_KEY, XFORCE credentials |
| OTX Pulses | Failed | OTX_API_KEY not set | Threat Intel Service + API Key |
| X-Force Checks | "Checking..." | XFORCE credentials missing | Threat Intel Service + Credentials |
| Threats Page | 0 Data | No packet capture or detection | Traffic Capture + Detection Services |
| AI Detection | 0 Detections | Model not loaded or no packets | AI Service + Model Files + Packets |
| Analytics | 0 Threats | Detection services not processing | All detection services + packet flow |

---

## File Structure Summary

**API Routes**:
- Dashboard API: `/home/user/fyp/dids-dashboard/api/dashboard.py` (970 lines)
- App API: `/home/user/fyp/dids-dashboard/routes/api.py` (243 lines)
- Rules API: `/home/user/fyp/dids-dashboard/api/rules.py`

**Services**:
- Threat Intelligence: `/home/user/fyp/microservices/threat-intel/app.py` (750+ lines)
- AI Detection: `/home/user/fyp/microservices/ai-detection/app.py` (300 lines)
- API Gateway: `/home/user/fyp/microservices/api-gateway/app.py` (400+ lines)
- Signature Detection: `/home/user/fyp/microservices/signature-detection/app.py` (300+ lines)

**Models**:
- Location: `/home/user/fyp/dids-dashboard/model/`
- Main: `dids_final.keras`
- Supporting: `scaler.pkl`, `label_encoder.pkl`, `feature_names.json`

