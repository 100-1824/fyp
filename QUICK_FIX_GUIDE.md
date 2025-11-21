# DIDS Quick Fix Guide - What's Not Working

## Critical Issues & Root Causes

### 1. THREAT INTELLIGENCE PAGE FAILURES

**Problem**: "Failed to load pulses" and "Failed to load indicators"

**Root Cause**: Missing API credentials
- `OTX_API_KEY` environment variable is empty
- `XFORCE_API_KEY` and `XFORCE_API_PASSWORD` are empty

**Location of Issue**:
- Service: `/home/user/fyp/microservices/threat-intel/app.py`
- Lines 675-676: Checks if OTX_API_KEY exists
- Lines 104-106: Checks if XFORCE credentials exist

**Fix**:
```bash
# Set these environment variables:
export OTX_API_KEY=your_otx_api_key_here
export XFORCE_API_KEY=your_xforce_key_here
export XFORCE_API_PASSWORD=your_xforce_password_here

# Or add to docker-compose .env file:
# OTX_API_KEY=your_key
# XFORCE_API_KEY=your_key
# XFORCE_API_PASSWORD=your_password
```

**IBM X-Force showing "Checking..."**: Same issue - credentials missing

**AlienVault OTX showing "Checking..."**: Same issue - API key missing

---

### 2. THREATS PAGE SHOWING ALL ZEROS

**Problem**: No threat data displayed

**Root Cause**: Multi-part issue:
1. Packet capture service not running or not collecting traffic
2. Detection services not processing the packets
3. Data not flowing through the pipeline

**Files Involved**:
- Frontend: `/home/user/fyp/dids-dashboard/templates/threats.html`
- API Endpoint: `/api/combined-threats` (routes/api.py lines 102-124)
- Data Sources:
  - `threat_service.get_recent_threats()` (signature-based)
  - `ai_service.get_recent_detections()` (ML-based)

**Troubleshooting Steps**:

1. Check if packet capture is running:
```bash
curl http://localhost:8000/api/capture/status
# Should return: {"active": true, "flow_count": X}
```

2. Check if there are any threats at all:
```bash
curl http://localhost:8000/api/threats
curl http://localhost:8000/api/combined-threats
# Should return array of threat objects, not empty
```

3. Verify the network interface is correct:
```bash
# In config.py, DEFAULT_INTERFACE should match your system
# Check available interfaces:
ip link show
```

4. Check packet stats:
```bash
curl http://localhost:8000/api/stats
# Look for: total_packets > 0
```

---

### 3. AI DETECTION SHOWING 0 DETECTIONS

**Problem**: "0 detections" displayed, empty charts

**Root Cause**: AI model not loaded properly

**Why Model Fails to Load**:
1. Model files not mounted in Docker container
2. Files missing from `/home/user/fyp/dids-dashboard/model/`
3. Incorrect path configuration in Docker

**Files Required**:
```
/home/user/fyp/dids-dashboard/model/
├── dids_final.keras       (MUST EXIST - main model)
├── scaler.pkl             (MUST EXIST - feature scaling)
├── label_encoder.pkl      (MUST EXIST - attack type mapping)
└── feature_names.json     (MUST EXIST - 77 features)
```

**Check Model Status**:
```bash
curl http://localhost:5003/health
# Look for: {"model_loaded": true/false}
```

**Docker Volume Configuration** (docker-compose.yml):
```yaml
ai-detection:
  volumes:
    - ./dids-dashboard/model:/app/model:ro  # CRITICAL!
```

**Verify Files Exist**:
```bash
ls -la /home/user/fyp/dids-dashboard/model/
# All 4 files should be present
```

**If Files Missing**:
- They should have been created during ML training
- Check: `/home/user/fyp/ml-training/` for training scripts
- Or restore from: training_data.tar.gz

---

### 4. ANALYTICS SHOWING 0 THREATS (WITH PACKETS)

**Problem**: Packets captured but no threats detected

**Root Cause**: Detection pipeline not processing packets

**Data Flow Problem**:
```
Packets Captured → Threat Detection Service → Stored in threat_service
                       ↓
                 AI Detection Service
                       ↓
                  /api/combined-threats endpoint
```

**If Packets > 0 but Threats = 0**:

1. Check if detection services are healthy:
```bash
curl http://localhost:5002/health  # Signature detection
curl http://localhost:5003/health  # AI detection
```

2. Check if packet capture is sending data to detection:
```bash
curl http://localhost:8000/api/api/detection-overview
# Should show threat statistics
```

3. Verify services are connected:
```bash
curl http://localhost:5000/health  # API Gateway
# Check services_health for all services
```

4. Possible causes:
   - Captured traffic is benign (no actual threats)
   - Detection rules too strict
   - AI model not detecting patterns in traffic
   - Detection service timeouts

---

## Quick Health Check Script

```bash
#!/bin/bash
echo "=== DIDS Health Check ==="

echo "1. API Gateway Health:"
curl -s http://localhost:5000/health | grep -o '"status":"[^"]*"'

echo "2. Threat Intelligence Service:"
curl -s http://localhost:5005/health | grep -o '"status":"[^"]*"'

echo "3. AI Detection Service (Model Loaded?):"
curl -s http://localhost:5003/health | grep -o '"model_loaded":[^,}]*'

echo "4. Signature Detection Service:"
curl -s http://localhost:5002/health | grep -o '"status":"[^"]*"'

echo "5. Dashboard Stats:"
curl -s http://localhost:8000/api/stats | grep -E '"total_packets":|"threat_count":'

echo "6. Packet Capture Status:"
curl -s http://localhost:8000/api/capture/status | grep -o '"active":[^,}]*'

echo "7. Configuration Check:"
echo "   OTX_API_KEY set: $([ -n "$OTX_API_KEY" ] && echo 'YES' || echo 'NO')"
echo "   XFORCE_API_KEY set: $([ -n "$XFORCE_API_KEY" ] && echo 'YES' || echo 'NO')"
echo "   Network interface: $DEFAULT_INTERFACE"
```

---

## Configuration File Locations

### Main Config
- **File**: `/home/user/fyp/dids-dashboard/config.py`
- **Key Settings**: MONGO_URI, microservice URLs, API keys, network interface

### Environment Variables Needed
- `FLASK_ENV=development` or `production`
- `MONGO_URI=mongodb://localhost:27017/dids_dashboard`
- `DEFAULT_INTERFACE=eth0` (match your system)
- `OTX_API_KEY=...` (Threat Intelligence)
- `XFORCE_API_KEY=...` (IBM X-Force)
- `XFORCE_API_PASSWORD=...` (IBM X-Force)

### Docker Environment
- **File**: `.env` in project root (for docker-compose)
- Must set XFORCE and OTX credentials for Threat Intelligence

---

## Service Ports Reference

| Service | Port | URL | Purpose |
|---------|------|-----|---------|
| Flask Dashboard | 8000 | http://localhost:8000 | Main UI |
| API Gateway | 5000 | http://localhost:5000 | Service orchestrator |
| Traffic Capture | 5001 | http://localhost:5001 | Packet collection |
| Signature Detection | 5002 | http://localhost:5002 | Pattern-based IDS |
| AI Detection | 5003 | http://localhost:5003 | ML threat detection |
| RL Detection | 5004 | http://localhost:5004 | Reinforcement learning |
| Threat Intelligence | 5005 | http://localhost:5005 | Threat lookups |

---

## What Needs to Be Running

### Minimum (for basic functionality)
1. dids-dashboard (Flask) - Port 8000
2. MongoDB (for data storage)

### For Full Features
1. All microservices (5000-5005)
2. PostgreSQL (for persistence)
3. Redis (for caching)
4. RabbitMQ (for messaging)

### Critical for Specific Features

**For Threat Intelligence**:
- Threat Intelligence Service (5005)
- API credentials: OTX_API_KEY at minimum

**For Threats Detection**:
- API Gateway (5000)
- Threat Detection Service (5002)
- Traffic Capture Service (5001)
- Packet capture running and network interface configured

**For AI Detection**:
- AI Detection Service (5003)
- Model files mounted correctly
- Packets being captured and routed to service

---

## Summary of Configuration Changes Needed

| Feature | Issue | Fix |
|---------|-------|-----|
| Threat Intel Pulses | OTX_API_KEY missing | Set environment variable |
| X-Force Status | Credentials missing | Set XFORCE_API_KEY and XFORCE_API_PASSWORD |
| Threats Page | Packet capture not working | Verify DEFAULT_INTERFACE is correct |
| AI Detection | Model not loaded | Verify model files exist and Docker volume mounted |
| Analytics | Services not running | Start all microservices and check health |

