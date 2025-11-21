# THREAT DETECTION SYSTEM ANALYSIS: Why Only SIG Detections Appear

## EXECUTIVE SUMMARY
The threat detection system has AI, ML, and RL agent services implemented and configured, but they are **not appearing in the threat display** due to a combination of initialization issues, model loading problems, and potential execution flow issues.

---

## 1. ARCHITECTURE OVERVIEW

### A. Detection Services (All Implemented)
The system has THREE detection mechanisms:
1. **Signature-Based Detection** (ThreatDetectionService) - WORKING
2. **AI/ML Detection** (AIDetectionService) - IMPLEMENTED but ISSUES
3. **RL Agent Detection** (RLDetectionService) - IMPLEMENTED but ISSUES

### B. Service Initialization Flow (app.py, lines 73-148)
1. Rule Engine initialized → ThreatDetectionService
2. AI Service initialized → AIDetectionService
3. RL Service initialized → RLDetectionService
4. All passed to PacketCaptureService

---

## 2. ROOT CAUSES IDENTIFIED

### ISSUE 1: MISSING CRITICAL FILES - SCALER.PKL
**Location**: `/home/user/fyp/dids-dashboard/model/`

**Problem**:
- AI Service (ai_detection.py, lines 119-132) tries to load `scaler.pkl`
- RL Service (rl_detection.py, lines 80-86) tries to load `scaler.pkl`
- **File is MISSING** from the model directory

**Impact**:
```
Files Present:
✓ dids_final.keras (AI model)
✓ double_dqn_final.keras (RL model)
✓ feature_names.json (42 features)
✓ dids_config.json (class names)
✓ dids_metrics.json (model metrics)

✗ scaler.pkl (MISSING - CRITICAL)
✗ label_encoder.pkl (MISSING - FALLBACK to config, works)
```

**Code References**:
- ai_detection.py, lines 120-130: Loads scaler, logs warning if missing
- rl_detection.py, lines 81-86: Loads scaler, continues if missing

**Result**: 
- AI/RL services attempt to normalize features without proper scaler
- Falls back to simple normalization (line 378 in ai_detection.py)
- This can significantly impact detection accuracy

---

### ISSUE 2: MODEL LOADING AND is_ready() CHECKS
**Location**: Multiple service initialization points

**Problem**:

In app.py (lines 112-132):
```python
ai_service = AIDetectionService(app.config, model_path=model_path)

if ai_service.is_ready():
    # Service is used
else:
    ai_service = None  # ← DISABLES AI SERVICE
```

In app.py (lines 134-148):
```python
rl_service = RLDetectionService(app.config, model_path=rl_model_path)

if rl_service.is_ready():
    # Service is used
else:
    rl_service = None  # ← DISABLES RL SERVICE
```

**is_ready() Conditions**:
- AI (ai_detection.py, lines 681-687): ALL THREE must be loaded
  ```python
  return (
      self.model is not None          # Keras model
      and self.label_encoder is not None     # Label encoder
      and self.feature_names is not None     # Feature names
  )
  ```
  
- RL (rl_detection.py, lines 360-362): Only model needed
  ```python
  return self.rl_model is not None
  ```

**Critical Check**: If model loading fails at any point, ai_service/rl_service become None globally
- When None, ALL detection endpoints return empty arrays:
  - `/api/ai-detections` → returns []
  - `/api/rl-decisions` → returns []
  - `/api/combined-threats` → only has signature detections

---

### ISSUE 3: AI/RL SERVICE NOT BEING CALLED IN PACKET ANALYSIS
**Location**: packet_capture.py

**Analysis**:
The `analyze_packet()` method (lines 208-279) has conditional calls:
```python
# Line 250-264: AI Detection
if self.ai_service and self.ai_service.is_ready() and self.flow_tracker:
    # AI detection runs
    
# NOTE: There is NO RL DETECTION call in analyze_packet()
# RL is ONLY called in inject_simulated_packet() (line 646)
```

**Problem Identified**:
1. In **live packet capture** (sniff mode):
   - AI detection is called if service is ready
   - **RL detection is NEVER called** ← Live traffic gets NO RL analysis
   
2. In **simulated packet injection** (testing mode):
   - Both AI and RL are called (lines 612-669)

**Impact**: RL agent never processes live captured packets, only simulated ones

---

### ISSUE 4: CONFIDENCE THRESHOLDS TOO HIGH
**Location**: ai_detection.py, lines 42-44

**Problem**:
```python
self.confidence_threshold = 0.50  # 50% minimum
self.consecutive_threshold = 1    # Must detect once to report
```

But then in _should_report_detection() (line 547):
```python
if confidence < 0.60 and tracker["count"] < self.consecutive_threshold:
    return False
```

**Analysis**:
- Confidence threshold is 50%
- But detections below 60% require consecutive detections
- This is STRICTER than configured

**Also** (ai_detection.py, lines 519-521):
```python
if confidence < self.confidence_threshold:
    return False
```

This means detection below 50% are filtered OUT

**For RL** - No confidence threshold filtering, but:
- RL only reports on alert/block actions (line 269 in packet_capture.py)
- RL might be choosing "allow" by default

---

### ISSUE 5: FEATURE EXTRACTION MIGHT BE TOO SIMPLISTIC
**Location**: ai_detection.py, lines 188-266

**Problem**: 
Feature extraction from single packets:
```python
# Line 217-260: extract_flow_features()
# Returns mostly hardcoded/default values:
"Fwd Packet Length Max": packet_size,    # Just packet size
"Fwd Packet Length Min": packet_size,    # Same value
"Fwd Packet Length Mean": packet_size,   # Same value
"Fwd Packet Length Std": 0.0,            # Always zero
"Flow Bytes/s": packet_size,             # Just packet size
"Flow IAT Mean": 0.0,                    # All zero
"Flow IAT Std": 0.0,                     # All zero
...
```

**Impact**:
- Feature vector doesn't represent actual network behavior
- Same features for most packets
- Model has limited context to make meaningful predictions

**Also** aggregate_flow_features() (lines 268-334):
- Returns mostly hardcoded values, not real aggregates
- Doesn't actually aggregate multiple packets
- Returns same values every time

---

## 3. DISPLAY AND API ISSUES

### A. API Endpoint Logic (routes/api.py)

**Combined Threats Endpoint** (lines 131-174):
```python
def combined_threats():
    combined = []
    
    # Add signature threats
    sig_threats = threat_service.get_recent_threats(limit=limit)
    for threat in sig_threats:
        threat["detection_method"] = "signature"  # ← Sets SIG
        combined.append(threat)
    
    # Add AI threats IF service ready
    if ai_service and ai_service.is_ready():
        ai_threats = ai_service.get_recent_detections(limit=limit)
        for threat in ai_threats:
            threat["detection_method"] = "ai"  # ← Sets AI
            combined.append(threat)
    
    # Add RL decisions IF service ready
    if rl_service and rl_service.is_ready():
        rl_decisions = rl_service.get_recent_decisions(limit=limit)
        # ... converts to threat format
        threat["detection_method"] = "rl"  # ← Sets RL
        combined.append(threat)
    
    return jsonify(combined[:limit])
```

**Issue**: If ai_service or rl_service is None (due to init failure), these blocks never execute
- Result: Only signature detections returned
- Frontend receives ONLY SIG detection_method in combined list

### B. Frontend Display (threats.html)

**Detection Method Filter** (line 1314):
```javascript
if (detectionFilter === 'ai' && t.detection_method !== 'ai') return false;
if (detectionFilter === 'rl' && t.detection_method !== 'rl') return false;
```

**Stats Calculation** (lines 1347-1356):
```javascript
const sigThreats = filteredData.filter(
    t => t.detection_method === 'signature' || !t.detection_method
).length;
const aiThreats = filteredData.filter(t => t.detection_method === 'ai').length;
const rlThreats = filteredData.filter(t => t.detection_method === 'rl').length;
```

**Display** (line 1368):
```javascript
detectionBadge = '<span class="detection-badge detection-sig">SIG</span>';
```

**Issue**: Frontend works correctly IF data is provided
- Problem is UPSTREAM in data generation, not display

---

## 4. DETECTION FLOW ANALYSIS

### Signature-Based (WORKS)
```
Packet → PacketCaptureService.analyze_packet()
  → threat_service._check_signature_threats()
    → threat_service.log_threat()
      → threat_service.signature_detections.append()
  → Stored in threat_service.signature_detections
  
/api/threats → threat_service.get_recent_threats()
/api/combined-threats → includes sig threats with detection_method="signature"
```

### AI-Based (ISSUES)
```
Packet → PacketCaptureService.analyze_packet()
  → IF ai_service.is_ready() AND ai_service IS NOT None:
    → ai_service.detect_threat(packet_info)
      → Extracts features (mostly hardcoded)
      → Runs model prediction
      → Stores in ai_service.detections
  → Otherwise: NO AI ANALYSIS

/api/ai-detections → ai_service.get_recent_detections() (EMPTY if not ready)
/api/combined-threats → IF ai_service IS NOT None: adds AI detections
```

### RL Agent (ISSUES)
```
LIVE PACKETS:
Packet → PacketCaptureService.analyze_packet()
  → RL NEVER CALLED (no rl_service.decide_action)
  → NO RL DETECTIONS IN LIVE MODE

SIMULATED PACKETS (Testing):
Packet → PacketCaptureService.inject_simulated_packet()
  → IF rl_service.is_ready() AND rl_service IS NOT None:
    → rl_service.decide_action(packet_info, ai_detection)
      → Extracts features
      → Gets Q-values
      → Returns action decision
      → Stores in rl_service.detections
  → Otherwise: FALLBACK POLICY (basic rules)

/api/rl-decisions → rl_service.get_recent_decisions()
/api/combined-threats → IF rl_service IS NOT None: adds RL decisions
```

---

## 5. DETAILED ROOT CAUSE SUMMARY

### Primary Issue: SERVICE INITIALIZATION FAILURE
If either ai_service or rl_service fails to load:
1. App sets service to None (app.py, lines 132 & 148)
2. API checks `if ai_service is not None` before using it
3. Combined threats endpoint skips these services
4. Frontend only receives signature detections
5. User sees ONLY SIG badges

### Secondary Issue: MISSING SCALER.PKL
Even if models load:
1. Scaler file missing causes features to use fallback normalization
2. Model predictions may be inaccurate
3. Confidence scores might be wrong
4. Detections might be filtered by confidence threshold

### Tertiary Issue: RL NOT CALLED IN LIVE MODE
1. RL agent implemented but never invoked for live packets
2. Only gets called in simulated packet injection
3. Users never see RL detections unless using simulator

### Quaternary Issue: SIMPLIFIED FEATURE EXTRACTION
1. Features extracted from single packets, not flows
2. Many features hardcoded as constants
3. Limited discriminative power
4. Model can't distinguish attack patterns properly

---

## 6. CONFIGURATION AND THRESHOLDS

### AI Detection Thresholds
- Confidence threshold: 50%
- For <60% confidence: requires consecutive detections
- Cache TTL: 10 seconds (prevents duplicate alerts)

### Benign Traffic Filtering
- Detections classified as "Benign" are filtered out (ai_detection.py, line 463)
- Model might be too conservative (classifying attacks as benign)

---

## 7. EVIDENCE FROM CODE

### Evidence 1: Service Becomes None on Failure
File: app.py, lines 117-132
```python
ai_service = AIDetectionService(app.config, model_path=model_path)

if ai_service.is_ready():
    app.logger.info("✓ AI detection service initialized successfully")
else:
    app.logger.warning("⚠️  AI detection service not ready...")
    ai_service = None  # ← BECOMES NULL
```

### Evidence 2: API Checks for None
File: routes/api.py, lines 78-79
```python
if ai_service and ai_service.is_ready():  # ← Double check
    return jsonify(ai_service.get_recent_detections(limit=20))
return jsonify([])  # ← Returns empty if None
```

### Evidence 3: Missing Scaler
File: `/home/user/fyp/dids-dashboard/model/` directory listing:
- scaler.pkl NOT FOUND ❌
- dids.keras FOUND ✓
- feature_names.json FOUND ✓

### Evidence 4: RL Not Called in Live Mode
File: packet_capture.py, lines 208-279
```python
def analyze_packet(self, pkt):
    # ... signature check
    # ... AI check with is_ready()
    # NO RL CHECK ← RL NEVER CALLED
    return record
```

But in inject_simulated_packet() (lines 646-669):
```python
if self.rl_service and self.rl_service.is_ready():
    rl_decision = self.rl_service.decide_action(...)
    # ← RL IS CALLED HERE
```

---

## 8. WHY ONLY SIG DETECTIONS SHOW

### The Chain Reaction:
1. App starts and tries to load AI model
2. AI service might fail to load (various reasons)
3. ai_service set to None in app.py
4. API checks `if ai_service is not None` → fails
5. AI detections not returned from API
6. Frontend only receives signature detections
7. User sees ONLY SIG badges

### Same for RL:
1. RL service loads (might be OK)
2. But never called for live packets (not in analyze_packet)
3. Only called for simulated packets
4. User tests with simulator → sees RL detections
5. User runs live traffic → NO RL detections


---

## 9. RECOMMENDED SOLUTIONS

### SOLUTION 1: CREATE OR GENERATE MISSING SCALER.PKL
**Priority**: CRITICAL - Required for proper feature normalization

**Steps**:
1. Check if scaler exists in ML training directory
2. If not, regenerate using training data:
```python
from sklearn.preprocessing import StandardScaler
import pickle

# After loading training data
scaler = StandardScaler()
scaler.fit(X_train)  # Fit on training features
pickle.dump(scaler, open('model/scaler.pkl', 'wb'))
```

**Impact**: Enables proper feature normalization for both AI and RL models

---

### SOLUTION 2: ADD RL DETECTION TO LIVE PACKET ANALYSIS
**Priority**: HIGH - RL agent never processes live traffic

**File**: dids-dashboard/services/packet_capture.py

**Change** (after line 264, before line 266):
```python
# 3. Check RL-based decisions if RL service is available
if self.rl_service and self.rl_service.is_ready():
    rl_decision = self.rl_service.decide_action(packet_info, ai_detection)
    
    if rl_decision and rl_decision.get("action") in ["alert", "block"]:
        threat_detected = True
        logger.info(
            f"🤖 RL Decision: {rl_decision['action']} "
            f"({rl_decision['confidence']}% confidence)"
        )
```

**Impact**: Enables RL agent to analyze live captured packets, not just simulated ones

---

### SOLUTION 3: IMPROVE FEATURE EXTRACTION FOR FLOW CONTEXT
**Priority**: MEDIUM - Current features are too simplistic

**Current Issue** (ai_detection.py, lines 217-260):
- Extract_flow_features() uses mostly hardcoded values
- aggregate_flow_features() returns fixed values
- Features don't capture actual packet behavior

**Improvement**: Use actual flow aggregation:
```python
def extract_flow_features(self, packet_data: Dict[str, Any]) -> Optional[Dict[str, float]]:
    """Extract network flow features from packet data."""
    
    # Get actual values from packet
    packet_size = float(packet_data.get("size", 64))
    src = packet_data.get('source', '')
    dst = packet_data.get('destination', '')
    
    # Initialize flow key
    flow_key = f"{src}-{dst}"
    
    # Get aggregated stats from flow_tracker if available
    if hasattr(self, 'flow_stats') and flow_key in self.flow_stats:
        flow_info = self.flow_stats[flow_key]
        fwd_packets = flow_info.get('fwd_packets', [])
        bwd_packets = flow_info.get('bwd_packets', [])
        
        # Real aggregation
        fwd_lengths = [p['size'] for p in fwd_packets]
        bwd_lengths = [p['size'] for p in bwd_packets]
        
        features = {
            "Flow Duration": flow_info.get('duration', 1.0),
            "Fwd Packet Length Max": max(fwd_lengths) if fwd_lengths else packet_size,
            "Fwd Packet Length Min": min(fwd_lengths) if fwd_lengths else packet_size,
            "Fwd Packet Length Mean": sum(fwd_lengths)/len(fwd_lengths) if fwd_lengths else packet_size,
            # ... continue with real calculations
        }
    else:
        # Fallback to current implementation
        features = { ... }
    
    return features
```

**Impact**: Better detection accuracy by capturing actual network flow characteristics

---

### SOLUTION 4: ADJUST CONFIDENCE THRESHOLDS
**Priority**: MEDIUM - Current thresholds may be too strict

**File**: dids-dashboard/services/ai_detection.py

**Changes**:
1. Lower confidence threshold for more sensitive detection:
```python
self.confidence_threshold = 0.40  # Lower from 0.50
```

2. Remove the 60% special case:
```python
# In _should_report_detection(), replace line 547:
# BEFORE: if confidence < 0.60 and tracker["count"] < self.consecutive_threshold:
# AFTER: if confidence < self.confidence_threshold and tracker["count"] < self.consecutive_threshold:
```

3. Increase cache TTL for faster updates:
```python
self.cache_ttl = 5  # Lower from 10 seconds
```

**Impact**: More AI detections surface to the dashboard

---

### SOLUTION 5: ADD LOGGING TO DIAGNOSE SERVICE STATUS
**Priority**: MEDIUM - Hard to troubleshoot without visibility

**File**: dids-dashboard/routes/api.py

**Add new endpoint** (after line 129):
```python
@api_bp.route("/detection-services-status")
@login_required
def detection_services_status():
    """Get status of all detection services for debugging"""
    return jsonify({
        "signature_service": {
            "initialized": threat_service is not None,
            "threats_logged": len(threat_service.signature_detections) if threat_service else 0
        },
        "ai_service": {
            "initialized": ai_service is not None,
            "ready": ai_service.is_ready() if ai_service else False,
            "model_loaded": ai_service.model is not None if ai_service else False,
            "encoder_loaded": ai_service.label_encoder is not None if ai_service else False,
            "detections": len(ai_service.detections) if ai_service else 0,
            "info": ai_service.get_model_info() if ai_service else {}
        },
        "rl_service": {
            "initialized": rl_service is not None,
            "ready": rl_service.is_ready() if rl_service else False,
            "model_loaded": rl_service.rl_model is not None if rl_service else False,
            "decisions": len(rl_service.detections) if rl_service else 0,
            "stats": rl_service.get_statistics() if rl_service else {}
        }
    })
```

**Impact**: Enables easy debugging of which services are actually initialized

---

### SOLUTION 6: ADD INITIALIZATION CHECKS IN FRONTEND
**Priority**: LOW - Help user understand what's available

**File**: dids-dashboard/templates/threats.html

**Add to page load**:
```javascript
// Check which detection methods are available
fetch('/api/detection-services-status')
    .then(r => r.json())
    .then(status => {
        console.log('Detection Services Status:', status);
        
        // Warn if services unavailable
        if (!status.ai_service.ready) {
            console.warn('AI Detection Service not available');
        }
        if (!status.rl_service.ready) {
            console.warn('RL Detection Service not available');
        }
        
        // Disable filters for unavailable services
        if (!status.ai_service.ready) {
            document.querySelector('[value="ai"]').disabled = true;
        }
        if (!status.rl_service.ready) {
            document.querySelector('[value="rl"]').disabled = true;
        }
    });
```

**Impact**: Users understand why certain filters are unavailable

---

## 10. TESTING AND VERIFICATION

### Test 1: Verify Services Load
**Command**: Check Flask startup logs
```
grep -E "AI detection|RL detection|ready" application.log
```

**Expected Output**:
```
✓ AI detection service initialized successfully
✓ RL detection service initialized successfully
```

**If Seeing**:
```
⚠️  AI detection service not ready
⚠️  RL detection service not ready
```
→ Services failed to initialize, check model files

---

### Test 2: Check Model Files
**Command**:
```bash
ls -la /home/user/fyp/dids-dashboard/model/
```

**Expected Files**:
- dids_final.keras ✓
- double_dqn_final.keras ✓
- feature_names.json ✓
- dids_config.json ✓
- scaler.pkl ✗ (MISSING)
- label_encoder.pkl ✗ (OK - fallback to config)

---

### Test 3: Test with Simulated Packets
**Command** (from dids-dashboard directory):
```bash
python3 tests/ddos_simulator.py --continuous --interval 2
```

**Verify**: Check threats.html for AI/RL detections while simulator runs

---

### Test 4: API Endpoint Testing
**Check endpoint responses**:
```bash
curl http://localhost:8000/api/ai-detections
curl http://localhost:8000/api/rl-decisions
curl http://localhost:8000/api/combined-threats
```

**Expected**: 
- Non-empty arrays for each endpoint if services working
- At least some entries with detection_method="ai" or "rl"

---

## 11. SUMMARY TABLE

| Issue | Severity | Root Cause | Impact | Solution |
|-------|----------|-----------|--------|----------|
| Missing scaler.pkl | CRITICAL | Feature files not generated | Improper normalization | Regenerate from training |
| Service init failure | HIGH | Model loading issues | AI/RL unavailable | Check model files, logs |
| RL not called in live mode | HIGH | Missing call in analyze_packet | RL never used for live traffic | Add RL call to analyze_packet |
| Simplified features | MEDIUM | Hardcoded feature values | Low detection accuracy | Use real flow aggregation |
| High thresholds | MEDIUM | Strict filtering rules | Fewer detections reported | Lower confidence threshold |
| Lack of visibility | MEDIUM | No diagnostic endpoint | Hard to troubleshoot | Add status endpoint |

---

## 12. IMMEDIATE ACTION ITEMS

### Priority 1 (Do First):
1. [ ] Check application logs for service initialization status
2. [ ] Generate or locate scaler.pkl file
3. [ ] Verify all model files exist in /model/ directory
4. [ ] Test API endpoints to confirm services working

### Priority 2 (Do Next):
1. [ ] Add RL detection call to live packet analysis
2. [ ] Lower AI confidence thresholds
3. [ ] Add diagnostic endpoint
4. [ ] Test with simulated packets

### Priority 3 (Do Later):
1. [ ] Improve feature extraction with real flow aggregation
2. [ ] Add frontend visibility indicators
3. [ ] Optimize model prediction caching

