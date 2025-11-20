# DIDS Microservices Architecture

This directory contains the microservices implementation of the Distributed Intrusion Detection System (DIDS).

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                       API Gateway (:5000)                       │
│                  Routes requests to microservices               │
└───────────┬──────────────┬──────────────┬──────────────────────┘
            │              │              │
    ┌───────▼──────┐  ┌────▼─────┐  ┌────▼─────┐  ┌──────────┐
    │   Traffic    │  │Signature │  │    AI    │  │    RL    │
    │   Capture    │  │Detection │  │Detection │  │Detection │
    │   (:5001)    │  │ (:5002)  │  │ (:5003)  │  │ (:5004)  │
    └──────────────┘  └──────────┘  └──────────┘  └──────────┘
            │              │              │              │
            └──────────────┴──────────────┴──────────────┘
                                 │
                          ┌──────▼──────┐
                          │   MongoDB   │
                          │   (:27017)  │
                          └─────────────┘
```

## 📦 Microservices

### 1. **API Gateway** (`api-gateway/`)
- **Port**: 5000
- **Purpose**: Main entry point, routes requests to other services
- **Endpoints**:
  - `GET /health` - Health check
  - `POST /analyze/packet` - Analyze packet through all detection layers
  - `GET /traffic/recent` - Get recent traffic
  - `POST /capture/start` - Start packet capture
  - `POST /capture/stop` - Stop packet capture
  - `GET /statistics` - Aggregated statistics from all services

### 2. **Traffic Capture Service** (`traffic-capture/`)
- **Port**: 5001
- **Purpose**: Packet sniffing and preprocessing
- **Features**:
  - Real-time packet capture using Scapy
  - Protocol detection (TCP, UDP, ICMP)
  - TCP flag extraction
  - Traffic buffering
- **Endpoints**:
  - `GET /health`
  - `POST /capture/start`
  - `POST /capture/stop`
  - `GET /capture/status`
  - `GET /packets/recent`
  - `GET /statistics`

### 3. **Signature Detection Service** (`signature-detection/`)
- **Port**: 5002
- **Purpose**: Pattern-based threat detection
- **Features**:
  - Threat signature matching
  - Port scan detection
  - DNS flood detection
  - Payload pattern analysis
  - IP whitelisting
- **Endpoints**:
  - `GET /health`
  - `POST /detect` - Detect threats in packet data
  - `GET /detections/recent`
  - `GET /signatures` - List loaded signatures
  - `GET /statistics`
  - `GET /whitelist`
  - `POST /whitelist` - Add IP to whitelist

### 4. **AI Detection Service** (`ai-detection/`)
- **Port**: 5003
- **Purpose**: ML-based threat detection
- **Features**:
  - Deep learning model inference
  - 15+ attack type classification
  - Confidence scoring
  - Feature extraction
- **Endpoints**:
  - `GET /health`
  - `POST /detect` - Detect threat using ML model
  - `GET /model/info` - Get model information
  - `GET /statistics`

### 5. **RL Detection Service** (`rl-detection/`)
- **Port**: 5004
- **Purpose**: Reinforcement learning-based decision making
- **Features**:
  - Q-value based decisions
  - Action selection (Allow, Alert, Block)
  - Context-aware responses
  - Confidence scoring
- **Endpoints**:
  - `GET /health`
  - `POST /decide` - Make RL-based decision
  - `GET /statistics`

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.10+
- 8GB RAM minimum
- Trained ML models (from `ml-training/` and `rl-module/`)

### Local Development with Docker Compose

```bash
# Navigate to microservices directory
cd microservices

# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

### Individual Service Development

```bash
# Run a single service
cd microservices/api-gateway
pip install -r requirements.txt
python app.py

# Set environment variables
export FLASK_ENV=development
export LOG_LEVEL=DEBUG
export TRAFFIC_CAPTURE_URL=http://localhost:5001
```

## ☸️ Kubernetes Deployment

### Prerequisites

- Kubernetes cluster (AKS, EKS, GKE, or minikube)
- kubectl configured
- Container registry access

### Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace dids

# Create secrets
kubectl create secret generic dids-secrets \
  --from-literal=mongo-uri='mongodb://username:password@mongodb:27017/dids' \
  -n dids

# Deploy all services
kubectl apply -f k8s/microservices/ -n dids

# Check deployments
kubectl get pods -n dids
kubectl get services -n dids

# View logs
kubectl logs -f deployment/api-gateway -n dids
```

### Scale Services

```bash
# Scale signature detection
kubectl scale deployment signature-detection --replicas=3 -n dids

# Scale AI detection
kubectl scale deployment ai-detection --replicas=4 -n dids
```

## 🔧 Configuration

### Environment Variables

Common variables for all services:

```bash
FLASK_ENV=development|production
LOG_LEVEL=DEBUG|INFO|WARNING|ERROR
MONGO_URI=mongodb://host:port/database
```

Service-specific variables:

```bash
# API Gateway
TRAFFIC_CAPTURE_URL=http://traffic-capture:5001
SIGNATURE_DETECTION_URL=http://signature-detection:5002
AI_DETECTION_URL=http://ai-detection:5003
RL_DETECTION_URL=http://rl-detection:5004

# Feature flags
ENABLE_AI_DETECTION=true|false
ENABLE_RL_DETECTION=true|false
ENABLE_SIGNATURE_DETECTION=true|false
```

## 📊 API Usage Examples

### Analyze a Packet

```bash
curl -X POST http://localhost:5000/analyze/packet \
  -H "Content-Type: application/json" \
  -d '{
    "source": "192.168.1.100",
    "destination": "8.8.8.8",
    "protocol": "TCP",
    "size": 1024,
    "src_port": 54321,
    "dst_port": 443,
    "syn": 1,
    "ack": 0
  }'
```

Response:
```json
{
  "packet": {...},
  "detections": [
    {
      "detector": "signature",
      "threat_type": "Port Scan",
      "severity": "high",
      "confidence": 95.0
    }
  ],
  "rl_decision": {
    "action": "alert",
    "confidence": 87.5,
    "reason": "RL agent detected suspicious activity"
  },
  "final_action": {
    "action": "alert",
    "reason": "Suspicious activity detected",
    "confidence": 87.5
  }
}
```

### Get Statistics

```bash
curl http://localhost:5000/statistics
```

### Health Check All Services

```bash
curl http://localhost:5000/health
```

## 🧪 Testing

### Unit Tests

```bash
# Test individual service
cd microservices/signature-detection
pytest tests/

# Test all services
./run_tests.sh
```

### Integration Tests

```bash
# Start all services
docker-compose up -d

# Run integration tests
pytest integration_tests/
```

### Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test API Gateway
ab -n 1000 -c 10 http://localhost:5000/health

# Test packet analysis
ab -n 100 -c 5 -p test_packet.json -T application/json \
   http://localhost:5000/analyze/packet
```

## 📈 Monitoring

### Prometheus Metrics (TODO)

Each service exposes metrics at `/metrics`:

```bash
curl http://localhost:5001/metrics
```

### Health Checks

All services have `/health` endpoints:

```bash
# Check API Gateway
curl http://localhost:5000/health

# Check all services via gateway
curl http://localhost:5000/services
```

### Logs

```bash
# Docker Compose logs
docker-compose logs -f api-gateway

# Kubernetes logs
kubectl logs -f deployment/api-gateway -n dids

# Follow logs from all services
kubectl logs -f -l component=detection -n dids
```

## 🔐 Security

### Network Policies (K8s)

```yaml
# Allow only API Gateway to access detection services
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: detection-services-policy
spec:
  podSelector:
    matchLabels:
      component: detection
  ingress:
  - from:
    - podSelector:
        matchLabels:
          component: gateway
```

### Secrets Management

```bash
# Create secrets in Kubernetes
kubectl create secret generic dids-secrets \
  --from-literal=mongo-uri=$MONGO_URI \
  --from-literal=jwt-secret=$JWT_SECRET \
  -n dids
```

## 🐛 Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs service-name

# Check if port is already in use
lsof -i :5000

# Rebuild container
docker-compose build service-name
docker-compose up service-name
```

### Service Communication Issues

```bash
# Check network
docker network inspect microservices_dids-network

# Test service connectivity
docker exec dids-api-gateway curl http://traffic-capture:5001/health
```

### Model Not Loading

```bash
# Verify volume mounts
docker-compose exec ai-detection ls -la /app/model

# Check model files exist
ls -la dids-dashboard/model/
ls -la rl-module/trained_models/
```

## 🚧 Performance Tuning

### Resource Limits

Edit `docker-compose.yaml`:

```yaml
services:
  ai-detection:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
```

### Scaling Strategy

- **API Gateway**: 2-4 replicas
- **Traffic Capture**: 1 replica (single capture point)
- **Signature Detection**: 2-3 replicas
- **AI Detection**: 2-4 replicas (CPU/GPU intensive)
- **RL Detection**: 2-3 replicas

## 📝 Development Workflow

### Adding a New Microservice

1. Create service directory:
```bash
mkdir microservices/new-service
cd microservices/new-service
```

2. Create `app.py`, `Dockerfile`, `requirements.txt`

3. Add to `docker-compose.yaml`:
```yaml
new-service:
  build: ./new-service
  ports:
    - "5005:5005"
  networks:
    - dids-network
```

4. Create K8s deployment in `k8s/microservices/`

5. Update API Gateway to route to new service

### Making Changes

1. Make code changes
2. Rebuild container: `docker-compose build service-name`
3. Restart service: `docker-compose up -d service-name`
4. Test: `curl http://localhost:port/health`

## 🔄 CI/CD Pipeline (TODO)

```yaml
# .github/workflows/deploy.yml
name: Deploy Microservices

on:
  push:
    branches: [main]

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build and push Docker images
        run: |
          docker build -t $REGISTRY/api-gateway microservices/api-gateway
          docker push $REGISTRY/api-gateway
      - name: Deploy to Kubernetes
        run: kubectl apply -f k8s/microservices/
```

## 📚 Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Docker Documentation](https://docs.docker.com/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Microservices Patterns](https://microservices.io/patterns/index.html)

## 🤝 Contributing

1. Create feature branch
2. Make changes to specific microservice
3. Update tests
4. Submit pull request

## 📄 License

Part of the DIDS FYP project.
