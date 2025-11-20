# Comprehensive Packet Preprocessing Pipeline

Complete preprocessing pipeline for extracting 77 network flow features from raw packets for AI/RL detection models.

## Overview

The preprocessing pipeline transforms raw network packets into feature vectors suitable for machine learning models. It implements the complete CICIDS2017 feature set with 77 statistical and behavioral features.

## Architecture

```
Raw Packet (Scapy)
       ↓
PacketPreprocessor.extract_packet_info()
       ↓
Packet Info Dict
       ↓
EnhancedFlowTracker.update_flow()
       ↓
EnhancedFlowData (aggregated flow)
       ↓
EnhancedFlowData.compute_all_features()
       ↓
77 Features Dict
       ↓
PacketPreprocessor.extract_flow_features()
       ↓
Feature Vector (numpy array[77])
       ↓
PacketPreprocessor.normalize_features()
       ↓
Normalized Features (range: -5 to 5)
```

## Components

### 1. PacketPreprocessor

Main preprocessing class that handles packet parsing and feature extraction.

**Key Methods:**
- `extract_packet_info(packet)`: Extract raw information from Scapy packet
- `extract_flow_features(flow_data)`: Extract 77 features from flow
- `normalize_features(features)`: Normalize feature vector
- `preprocess_packet(packet, flow_tracker)`: Complete preprocessing pipeline

**Supported Protocols:**
- TCP (full feature extraction including flags, window size, sequence numbers)
- UDP (basic features, no flags)
- ICMP (type/code extraction)
- Other IP protocols (basic features)

### 2. EnhancedFlowData

Stores and computes features for a single network flow.

**Tracked Information:**
- Bidirectional packet lists with (size, timestamp, flags, window, header_len, payload_len)
- TCP flag counters (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)
- Window sizes (initial forward/backward)
- Active/Idle time periods
- Bulk transfer tracking

**Feature Categories:**
1. **Basic Flow Features** (14 features)
   - Destination Port, Flow Duration
   - Total Fwd/Bwd Packets, Total Fwd/Bwd Bytes
   - Packet length statistics (max, min, mean, std)

2. **Flow Rate Features** (6 features)
   - Flow Bytes/s, Flow Packets/s
   - Fwd Packets/s, Bwd Packets/s
   - IAT (Inter-Arrival Time) statistics

3. **IAT Features** (15 features)
   - Flow IAT: Mean, Std, Max, Min
   - Forward IAT: Total, Mean, Std, Max, Min
   - Backward IAT: Total, Mean, Std, Max, Min

4. **TCP Flag Features** (12 features)
   - Direction-specific PSH/URG flags
   - Total flag counts (FIN, SYN, RST, PSH, ACK, URG, ECE, CWR)

5. **Header Features** (3 features)
   - Forward/Backward header lengths
   - Duplicate feature for compatibility

6. **Packet Statistics** (5 features)
   - Min/Max/Mean/Std/Variance of packet lengths

7. **Ratio Features** (4 features)
   - Down/Up Ratio
   - Average Packet Size
   - Avg Fwd/Bwd Segment Size

8. **Bulk Transfer Features** (6 features)
   - Fwd/Bwd Avg Bytes/Bulk
   - Fwd/Bwd Avg Packets/Bulk
   - Fwd/Bwd Avg Bulk Rate

9. **Subflow Features** (4 features)
   - Subflow Fwd/Bwd Packets
   - Subflow Fwd/Bwd Bytes

10. **Window Features** (2 features)
    - Init_Win_bytes_forward/backward

11. **Active Features** (6 features)
    - act_data_pkt_fwd (packets with payload)
    - min_seg_size_forward
    - Active Mean/Std/Max/Min (activity periods)

12. **Idle Features** (4 features)
    - Idle Mean/Std/Max/Min (idle periods)

**Total: 77 Features**

### 3. EnhancedFlowTracker

Manages multiple concurrent flows with automatic cleanup.

**Features:**
- Bidirectional flow tracking (same flow for A→B and B→A)
- Automatic timeout-based cleanup
- Maximum flow limit with LRU eviction
- Thread-safe operations

**Configuration:**
- `flow_timeout`: Timeout for inactive flows (default: 120s)
- `max_flows`: Maximum concurrent flows (default: 10000)

### 4. PreprocessingService

High-level service that coordinates preprocessing and database integration.

**Key Methods:**
- `process_packet(packet)`: Process Scapy packet
- `process_packet_dict(packet_data)`: Process packet from API/dict
- `extract_features_from_flow(flow_id)`: Get features for specific flow
- `get_flow_info(flow_id)`: Get complete flow information
- `get_active_flows()`: List all active flows
- `get_statistics()`: Get preprocessing statistics
- `batch_store_flows()`: Store all flows in database

## Feature List (77 Features)

1. Destination Port
2. Flow Duration
3. Total Fwd Packets
4. Total Backward Packets
5. Total Length of Fwd Packets
6. Total Length of Bwd Packets
7. Fwd Packet Length Max
8. Fwd Packet Length Min
9. Fwd Packet Length Mean
10. Fwd Packet Length Std
11. Bwd Packet Length Max
12. Bwd Packet Length Min
13. Bwd Packet Length Mean
14. Bwd Packet Length Std
15. Flow Bytes/s
16. Flow Packets/s
17. Flow IAT Mean
18. Flow IAT Std
19. Flow IAT Max
20. Flow IAT Min
21. Fwd IAT Total
22. Fwd IAT Mean
23. Fwd IAT Std
24. Fwd IAT Max
25. Fwd IAT Min
26. Bwd IAT Total
27. Bwd IAT Mean
28. Bwd IAT Std
29. Bwd IAT Max
30. Bwd IAT Min
31. Fwd PSH Flags
32. Bwd PSH Flags
33. Fwd URG Flags
34. Bwd URG Flags
35. Fwd Header Length
36. Bwd Header Length
37. Fwd Packets/s
38. Bwd Packets/s
39. Min Packet Length
40. Max Packet Length
41. Packet Length Mean
42. Packet Length Std
43. Packet Length Variance
44. FIN Flag Count
45. SYN Flag Count
46. RST Flag Count
47. PSH Flag Count
48. ACK Flag Count
49. URG Flag Count
50. CWE Flag Count
51. ECE Flag Count
52. Down/Up Ratio
53. Average Packet Size
54. Avg Fwd Segment Size
55. Avg Bwd Segment Size
56. Fwd Header Length.1
57. Fwd Avg Bytes/Bulk
58. Fwd Avg Packets/Bulk
59. Fwd Avg Bulk Rate
60. Bwd Avg Bytes/Bulk
61. Bwd Avg Packets/Bulk
62. Bwd Avg Bulk Rate
63. Subflow Fwd Packets
64. Subflow Fwd Bytes
65. Subflow Bwd Packets
66. Subflow Bwd Bytes
67. Init_Win_bytes_forward
68. Init_Win_bytes_backward
69. act_data_pkt_fwd
70. min_seg_size_forward
71. Active Mean
72. Active Std
73. Active Max
74. Active Min
75. Idle Mean
76. Idle Std
77. Idle Max
78. Idle Min

## Usage

### Basic Usage

```python
from services.preprocessing_service import create_preprocessing_service
from scapy.all import sniff

# Create preprocessing service
preprocessing_service = create_preprocessing_service(
    db=mongo.db,  # Optional MongoDB database
    config={
        'flow_timeout': 120,
        'max_flows': 10000
    }
)

# Process a single packet
def packet_callback(packet):
    packet_info, features = preprocessing_service.process_packet(packet)

    if features is not None:
        print(f"Extracted {len(features)} features")
        # Use features for AI/RL detection
        prediction = ai_model.predict(features.reshape(1, -1))

# Sniff packets
sniff(prn=packet_callback, count=100)
```

### Processing Dictionary Data (API/Microservices)

```python
# Packet data from API
packet_data = {
    'timestamp': time.time(),
    'source': '192.168.1.100',
    'destination': '8.8.8.8',
    'protocol_name': 'TCP',
    'src_port': 54321,
    'dst_port': 443,
    'size': 1024,
    'flags': {'syn': 1, 'ack': 0, 'fin': 0, ...},
    'window': 65535,
    'header_length': 20,
    'payload_size': 1004
}

# Extract features
features = preprocessing_service.process_packet_dict(packet_data)

if features is not None:
    # Features are normalized and ready for ML/RL
    ai_result = ai_detector.detect(features)
    rl_decision = rl_agent.decide(features)
```

### Flow Information

```python
# Get active flows
active_flows = preprocessing_service.get_active_flows()
print(f"Tracking {len(active_flows)} flows")

# Get specific flow info
flow_info = preprocessing_service.get_flow_info(flow_id)
if flow_info:
    print(f"Flow {flow_id}:")
    print(f"  Duration: {flow_info['duration']:.2f}s")
    print(f"  Packets: {flow_info['total_packets']}")
    print(f"  Features: {len(flow_info['features'])}")

# Get statistics
stats = preprocessing_service.get_statistics()
print(f"Packets processed: {stats['packets_processed']}")
print(f"Features extracted: {stats['features_extracted']}")
print(f"Active flows: {stats['active_flows']}")
```

### Database Integration

```python
# Store all flows in database
preprocessing_service.batch_store_flows()

# Automatic packet storage (when process_packet called with store_db=True)
packet_info, features = preprocessing_service.process_packet(packet, store_db=True)
```

## Feature Normalization

Features are normalized using Min-Max normalization to [0, 1] range by default:

```python
normalized = (features - min) / (max - min)
```

Then clipped to [-5, 5] range to handle outliers.

Alternative normalization methods:
- **Standard (z-score)**: `(features - mean) / std`
- **None**: Raw features

## Performance Considerations

1. **Flow Tracking Overhead**
   - Each flow maintains packet history (size, timestamp, flags)
   - Memory usage: ~1-2KB per active flow
   - 10,000 flows ≈ 10-20MB RAM

2. **Feature Extraction Speed**
   - Packet parsing: ~0.1ms per packet
   - Flow update: ~0.2ms per packet
   - Feature extraction: ~1ms per flow (77 features)
   - Total: ~1.3ms per packet

3. **Cleanup Strategy**
   - Automatic cleanup every 60 seconds
   - Removes flows inactive for > flow_timeout
   - LRU eviction when max_flows exceeded

4. **Optimization Tips**
   - Increase `flow_timeout` for long-lived connections
   - Decrease `max_flows` to reduce memory usage
   - Use `batch_store_flows()` periodically instead of per-packet DB writes
   - Enable DB storage only for threat packets

## Integration with Detection Modules

### AI Detection

```python
from services.ai_detection import AIDetectionService

ai_detector = AIDetectionService()

# Extract features
features = preprocessing_service.process_packet_dict(packet_data)

# AI detection
result = ai_detector.detect(features)
print(f"Attack type: {result['attack_type']}")
print(f"Confidence: {result['confidence']:.2f}%")
```

### RL Detection

```python
from services.rl_detection import RLDetectionService

rl_agent = RLDetectionService()

# Extract features
features = preprocessing_service.process_packet_dict(packet_data)

# RL decision
decision = rl_agent.decide(features)
print(f"Action: {decision['action']}")  # allow, alert, block
print(f"Q-values: {decision['q_values']}")
```

### Signature Detection

```python
from services.signature_detection import SignatureDetectionService

sig_detector = SignatureDetectionService()

# Signature detection works on raw packet, but features can supplement
packet_info, features = preprocessing_service.process_packet(packet)

sig_result = sig_detector.detect(packet_info)
```

## Troubleshooting

### Issue: Missing Features

**Problem**: Not all 77 features are extracted

**Solution**: Check packet protocol - some features only apply to TCP. Non-TCP packets will have zeros for TCP-specific features.

### Issue: High Memory Usage

**Problem**: Too many flows tracked

**Solution**:
```python
# Reduce max_flows
service = create_preprocessing_service(config={'max_flows': 5000})

# Reduce flow_timeout
service = create_preprocessing_service(config={'flow_timeout': 60})

# Manual cleanup
service.cleanup_old_flows()
```

### Issue: Slow Feature Extraction

**Problem**: Feature extraction taking too long

**Solution**:
- Batch process packets instead of real-time
- Reduce feature set (modify FEATURE_NAMES)
- Use multiprocessing for parallel extraction

### Issue: NaN or Inf Values

**Problem**: Features contain invalid values

**Solution**: Normalization automatically handles this by clipping to [-5, 5] and replacing NaN/Inf with 0.

## Testing

```python
# Test preprocessing pipeline
from services.preprocessing_service import create_preprocessing_service
from scapy.all import IP, TCP

service = create_preprocessing_service()

# Create test packet
packet = IP(src='192.168.1.1', dst='8.8.8.8')/TCP(sport=12345, dport=80, flags='S')

# Process
packet_info, features = service.process_packet(packet)

assert features is not None
assert len(features) == 77
assert all(isinstance(f, (int, float)) for f in features)
assert all(-5 <= f <= 5 for f in features)  # Normalized range

print("✓ Preprocessing pipeline test passed")
```

## References

- [CICIDS2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICFlowMeter Features](https://github.com/ahlashkari/CICFlowMeter)
- Network Flow Analysis Papers
- NIDS Feature Engineering Best Practices
