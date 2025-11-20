# DIDS Architecture Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [Architectural Patterns](#architectural-patterns)
3. [Module Interconnections](#module-interconnections)
4. [Data Flow](#data-flow)
5. [Communication Protocols](#communication-protocols)
6. [Component Diagrams](#component-diagrams)

## System Overview

Deep Intrusion Detection System (DIDS) is built on a microservices architecture with three core detection layers working in harmony to provide comprehensive network security.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Network Traffic Layer                           │
│                    (Physical/Virtual Network Interface)                  │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Traffic Capture       │
                    │   (Scapy + Redis)       │
                    │   Port: 5001            │
                    └────────────┬────────────┘
                                 │
                                 │ Publishes to Redis
                                 │
            ┌────────────────────┼────────────────────┐
            │                    │                    │
┌───────────▼──────────┐ ┌──────▼────────┐ ┌────────▼──────────┐
│  Signature Detection │ │   AI Detection │ │   RL Detection    │
│   (Suricata)         │ │  (TensorFlow)  │ │  (Double DQN)     │
│   Port: 5002         │ │   Port: 5003   │ │   Port: 5004      │
└───────────┬──────────┘ └───────┬────────┘ └────────┬──────────┘
            │                    │                    │
            └────────────────────┼────────────────────┘
                                 │
                                 │ Decision Fusion
                                 │
                    ┌────────────▼────────────┐
                    │  RL Agent (Final Say)   │
                    │  Actions: Allow/Alert/  │
                    │           Block          │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Alert Service         │
                    │   (RabbitMQ Consumer)   │
                    └────────────┬────────────┘
                                 │
                                 │ Stores in MongoDB
                                 │
                    ┌────────────▼────────────┐
                    │   Dashboard API         │
                    │   (Flask + PyMongo)     │
                    │   Port: 5000            │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Web Dashboard         │
                    │   (HTML/CSS/JS)         │
                    │   Port: 3000            │
                    └─────────────────────────┘
```

## Architectural Patterns

### 1. Microservices Architecture

Each detection module is an independent service:

- **Independent Deployment**: Services can be deployed, scaled, and updated independently
- **Technology Diversity**: Each service uses the most appropriate tech stack
- **Fault Isolation**: Failure in one service doesn't cascade to others

### 2. Event-Driven Communication

```
┌──────────────┐       Publish        ┌──────────────┐
│   Traffic    │──────Events────────→ │    Redis     │
│   Capture    │                      │   (PubSub)   │
└──────────────┘                      └──────┬───────┘
                                             │
                                   Subscribe │
                                             │
                        ┌────────────────────┼───────────────────┐
                        │                    │                   │
                   ┌────▼────┐         ┌────▼────┐        ┌─────▼────┐
                   │ Suricata│         │   AI    │        │    RL    │
                   │ Service │         │ Service │        │  Service │
                   └─────────┘         └─────────┘        └──────────┘
```

### 3. Decision Fusion Pattern

All three detection engines feed into the RL agent for final decision:

```python
def make_decision(traffic_features):
    # Layer 1: Signature Detection
    suricata_result = signature_detection(traffic_features)

    # Layer 2: Anomaly Detection
    ai_result = anomaly_detection(traffic_features)

    # Layer 3: RL Agent (Final Decision)
    state = combine_features(traffic_features, suricata_result, ai_result)
    action = rl_agent.predict(state)

    return action  # 0=Allow, 1=Alert, 2=Block
```

## Module Interconnections

### Traffic Capture → Detection Services

**Protocol**: Redis Pub/Sub
**Data Format**: JSON

```json
{
  "timestamp": "2025-01-20T12:00:00Z",
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.0.50",
  "src_port": 54321,
  "dst_port": 80,
  "protocol": "TCP",
  "packet_size": 1500,
  "tcp_flags": "SYN",
  "payload_preview": "GET /api/data HTTP/1.1..."
}
```

**Channel**: `traffic:packets`

### Detection Services → RL Agent

**Protocol**: HTTP REST API
**Endpoint**: `POST /predict`

```json
{
  "features": [0.5, 0.3, ..., 0.8],  // 77 features
  "signature_threat": false,
  "anomaly_score": 0.23
}
```

**Response**:
```json
{
  "action": 1,  // 0=Allow, 1=Alert, 2=Block
  "confidence": 0.95,
  "reasoning": "Anomaly detected in packet pattern"
}
```

### RL Agent → Alert Service

**Protocol**: RabbitMQ Message Queue
**Exchange**: `alerts`
**Routing Key**: By severity (low/medium/high/critical)

```json
{
  "alert_id": "uuid-1234",
  "timestamp": "2025-01-20T12:00:00Z",
  "severity": "high",
  "threat_type": "Port Scan",
  "source": "192.168.1.100",
  "action_taken": "block",
  "details": {...}
}
```

### Alert Service → MongoDB

**Database**: `dids`
**Collections**:
- `packets` - Raw traffic data (TTL: 7 days)
- `threats` - Detected threats (Permanent)
- `alerts` - Security alerts (Permanent)
- `detections` - Detection results (TTL: 30 days)

## Data Flow

### Real-Time Detection Flow

```
1. Packet Capture
   ├─→ Scapy captures packet on eth0
   ├─→ Extract metadata (IP, port, protocol, size)
   └─→ Publish to Redis channel "traffic:packets"

2. Parallel Detection (Async)
   ├─→ Suricata: Pattern matching against rules
   ├─→ AI Model: Anomaly detection (97.3% accuracy)
   └─→ Feature extraction for RL agent

3. RL Decision (Synchronous)
   ├─→ Combine all signals into state vector
   ├─→ RL agent predicts action (100% accuracy)
   └─→ Return decision: Allow/Alert/Block

4. Action Execution
   ├─→ If Block: Update firewall rules
   ├─→ If Alert: Send to RabbitMQ
   └─→ If Allow: Log benign traffic

5. Persistence
   ├─→ Alert Service consumes from RabbitMQ
   ├─→ Store in MongoDB (threats, alerts, detections)
   └─→ Update dashboard in real-time
```

### Training Data Flow

```
1. Data Collection
   ├─→ CICIDS2017 dataset (2.8M samples)
   ├─→ NSL-KDD dataset (148K samples)
   └─→ Live captured data (optional)

2. Preprocessing (ml-training/scripts/data_preprocessing.py)
   ├─→ Load raw CSV files
   ├─→ Handle missing values
   ├─→ Normalize features (StandardScaler)
   ├─→ Encode labels (LabelEncoder)
   └─→ Split: 70% train, 15% val, 15% test

3. Model Training
   ├─→ Anomaly Detection: CNN/LSTM (ml-training/scripts/train_model.py)
   └─→ RL Agent: Double DQN (rl_module/train_rl_agent.py)

4. Model Deployment
   ├─→ Save models to dids-dashboard/model/
   ├─→ Save scalers and encoders
   └─→ Version models in git
```

## Communication Protocols

### Service-to-Service Communication

| From | To | Protocol | Port | Purpose |
|------|-----|----------|------|---------|
| Traffic Capture | Redis | Redis Protocol | 6379 | Pub/Sub events |
| Signature Detection | Redis | Redis Protocol | 6379 | Subscribe to traffic |
| AI Detection | Redis | Redis Protocol | 6379 | Subscribe to traffic |
| RL Detection | Redis | Redis Protocol | 6379 | Subscribe to traffic |
| RL Agent | RabbitMQ | AMQP | 5672 | Publish alerts |
| Alert Service | RabbitMQ | AMQP | 5672 | Consume alerts |
| Alert Service | MongoDB | MongoDB Protocol | 27017 | Store data |
| Dashboard API | MongoDB | MongoDB Protocol | 27017 | Query data |
| Dashboard | Dashboard API | HTTP REST | 5000 | Fetch data |

### API Gateway Pattern

```
┌─────────────┐
│   Client    │
│  (Browser)  │
└──────┬──────┘
       │ HTTP
       │
┌──────▼──────────┐
│   API Gateway   │
│   (Port 5000)   │
└──────┬──────────┘
       │
       ├─→ /api/traffic/* ────→ Traffic Service (5001)
       ├─→ /api/threats/* ────→ Threat Service
       ├─→ /api/detect/*  ────→ Detection Services
       └─→ /api/stats/*   ────→ Statistics Service
```

## Component Diagrams

### Detection Engine Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Detection Engine                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │  Suricata    │  │   AI Model   │  │   RL Agent   │     │
│  │              │  │              │  │              │     │
│  │ • Rule DB    │  │ • CNN/LSTM   │  │ • Double DQN │     │
│  │ • IP Lists   │  │ • Scaler     │  │ • Target Net │     │
│  │ • Signatures │  │ • Encoder    │  │ • Experience │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │              │
│         └─────────────────┼─────────────────┘              │
│                           │                                 │
│                  ┌────────▼────────┐                       │
│                  │  Decision Fuser  │                       │
│                  │                  │                       │
│                  │ • Vote Weighting │                       │
│                  │ • Confidence     │                       │
│                  │ • Fail-safe      │                       │
│                  └────────┬─────────┘                       │
│                           │                                 │
│                  ┌────────▼────────┐                       │
│                  │  Action Handler  │                       │
│                  │                  │                       │
│                  │ • Firewall Rules │                       │
│                  │ • Alert Queue    │                       │
│                  │ • Logging        │                       │
│                  └──────────────────┘                       │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Dashboard Components

```
┌─────────────────────────────────────────────────────────────┐
│                      DIDS Dashboard                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Frontend (HTML/CSS/JS)                                     │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  • Real-time Charts (Chart.js)                       │  │
│  │  • Alert Table (DataTables)                          │  │
│  │  • Network Topology View                             │  │
│  │  • User Management UI                                │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │ AJAX/Fetch API                       │
│                     │                                       │
│  Backend (Flask)    │                                       │
│  ┌──────────────────▼───────────────────────────────────┐  │
│  │  Routes                                               │  │
│  │  ├─ /api/dashboard/overview                          │  │
│  │  ├─ /api/threats/recent                              │  │
│  │  ├─ /api/traffic/stats                               │  │
│  │  └─ /api/users/*                                     │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                       │
│  Services           │                                       │
│  ┌──────────────────▼───────────────────────────────────┐  │
│  │  • AIDetectionService                                │  │
│  │  • RLDetectionService                                │  │
│  │  • ThreatDetectionService                            │  │
│  │  • UserService                                       │  │
│  └──────────────────┬───────────────────────────────────┘  │
│                     │                                       │
│  Database (MongoDB) │                                       │
│  ┌──────────────────▼───────────────────────────────────┐  │
│  │  Collections:                                         │  │
│  │  • packets, threats, alerts                          │  │
│  │  • users, system_logs, statistics                    │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

## Scalability Considerations

### Horizontal Scaling

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    └────────┬────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
    ┌─────▼─────┐      ┌────▼─────┐      ┌────▼─────┐
    │ AI Det #1 │      │ AI Det #2│      │ AI Det #3│
    └───────────┘      └──────────┘      └──────────┘
```

**Scaling Strategies**:
- **Traffic Capture**: Single instance per network interface (cannot scale horizontally)
- **Signature Detection**: 2-3 replicas (CPU intensive)
- **AI Detection**: 2-4 replicas (GPU recommended)
- **RL Detection**: 2-3 replicas (lightweight)
- **Dashboard API**: 2-4 replicas (stateless)

### Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Packet Processing Rate | 10,000 pps | 8,500 pps |
| Detection Latency | <100ms | ~75ms |
| Dashboard Response Time | <1s | ~500ms |
| Concurrent Users | 500 | Tested: 200 |
| System Uptime | 99.9% | Monitored |

## Security Architecture

### Authentication Flow

```
┌──────────┐                ┌──────────────┐              ┌──────────┐
│  Client  │──── Login ────→│   Dashboard  │──── Verify ──│ MongoDB  │
│          │←─── Token ─────│     API      │←── User ────→│  (users) │
└──────────┘                └──────────────┘              └──────────┘
     │
     │ Include Token
     │
     ▼
┌──────────────┐
│  API Request │
│  + JWT Token │
└──────────────┘
```

### Role-Based Access Control (RBAC)

```python
Roles:
- admin: Full access (CRUD all resources)
- analyst: Read alerts, create reports
- viewer: Read-only access
- user: Basic dashboard access

Permissions Matrix:
                Admin   Analyst   Viewer   User
View Dashboard    ✓        ✓         ✓       ✓
View Alerts       ✓        ✓         ✓       ✓
Manage Users      ✓        ✗         ✗       ✗
Config Rules      ✓        ✓         ✗       ✗
System Settings   ✓        ✗         ✗       ✗
```

## Monitoring & Observability

### Metrics Collection

```
┌──────────────┐       Metrics        ┌──────────────┐
│   Services   │─────────────────────→│  Prometheus  │
└──────────────┘                      └──────┬───────┘
                                             │
                                    Scrape   │
                                             │
                                      ┌──────▼───────┐
                                      │   Grafana    │
                                      │  Dashboards  │
                                      └──────────────┘
```

**Key Metrics**:
- Packet processing rate
- Detection accuracy
- Alert volume
- System resource usage (CPU, RAM, Disk)
- API response times

### Logging Strategy

```
Service Logs → Stdout → Docker Logs → Aggregation → Analysis
                                     (Filebeat)   (ELK Stack)
```

## Deployment Architecture

### Kubernetes Deployment

```
┌────────────────────────────────────────────────────────────┐
│                     Kubernetes Cluster                      │
│  (Azure AKS - 2 nodes, Standard_DS2_v2)                   │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐  │
│  │  Namespace: dids-production                         │  │
│  │                                                      │  │
│  │  ┌──────────────┐  ┌──────────────┐               │  │
│  │  │ API Gateway  │  │ Traffic Cap  │               │  │
│  │  │ (2 replicas) │  │ (1 replica)  │               │  │
│  │  └──────────────┘  └──────────────┘               │  │
│  │                                                      │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────┐│  │
│  │  │  Signature   │  │  AI Detect   │  │ RL Agent ││  │
│  │  │ (2 replicas) │  │ (3 replicas) │  │(2 replic)││  │
│  │  └──────────────┘  └──────────────┘  └──────────┘│  │
│  │                                                      │  │
│  │  ┌──────────────┐  ┌──────────────┐               │  │
│  │  │   MongoDB    │  │    Redis     │               │  │
│  │  │(StatefulSet) │  │(StatefulSet) │               │  │
│  │  └──────────────┘  └──────────────┘               │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Network Policies

```yaml
# Allow traffic flow
Traffic Capture → All Services
Detection Services → RL Agent
RL Agent → Alert Service
Alert Service → MongoDB
Dashboard API → MongoDB
Dashboard → Dashboard API

# Block everything else (Zero Trust)
```

## Disaster Recovery

### Backup Strategy

```
MongoDB:
  - Daily full backups
  - Hourly incremental backups
  - Retention: 30 days
  - Storage: Azure Blob Storage

Models:
  - Versioned in git
  - Stored in artifact repository
  - Rollback capability

Configurations:
  - ConfigMaps in Kubernetes
  - Backed up with infrastructure code
```

### High Availability

```
Component          HA Strategy
─────────────────  ─────────────────────────────────
MongoDB            3-node replica set
Redis              Redis Sentinel (1 master, 2 slaves)
RabbitMQ           3-node cluster
Microservices      2+ replicas, different nodes
Dashboard          2+ replicas behind load balancer
```

## Future Architecture Enhancements

### Planned Improvements

1. **Distributed Tracing**: Implement Jaeger for request tracing across services
2. **Service Mesh**: Istio for advanced traffic management
3. **Multi-Region**: Deploy across multiple Azure regions
4. **Edge Computing**: Process traffic closer to source
5. **ML Model Registry**: Centralized model versioning (MLflow)
6. **Automated Scaling**: HPA based on custom metrics
7. **Chaos Engineering**: Regular resilience testing

---

**Document Version**: 1.0
**Last Updated**: 2025-01-20
**Maintained By**: DIDS Team
