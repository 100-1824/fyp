# Deployment Guide

## Overview

This guide provides comprehensive instructions for deploying the Deep Intrusion Detection System (DIDS) across various environments, from local development to production cloud deployments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Local Development Deployment](#local-development-deployment)
3. [Docker Compose Deployment](#docker-compose-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Azure Cloud Deployment](#azure-cloud-deployment)
6. [Production Best Practices](#production-best-practices)
7. [Monitoring and Operations](#monitoring-and-operations)
8. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

**Minimum (Development)**:
- CPU: 4 cores
- RAM: 16 GB
- Disk: 100 GB SSD
- Network: 1 Gbps

**Recommended (Production)**:
- CPU: 16+ cores
- RAM: 32+ GB
- Disk: 500 GB NVMe SSD
- Network: 10 Gbps
- GPU: NVIDIA T4 or better (optional, for ML acceleration)

### Software Requirements

```bash
# Required
- Docker 24.0+
- Docker Compose 2.20+
- Python 3.11+
- Node.js 18+
- Git

# For Kubernetes deployment
- kubectl 1.28+
- Helm 3.12+

# For Azure deployment
- Azure CLI 2.50+
- Terraform 1.5+
```

## Local Development Deployment

### Quick Start

```bash
# 1. Clone repository
git clone https://github.com/100-1824/fyp.git
cd fyp

# 2. Set up environment
cp .env.example .env
# Edit .env with your configuration

# 3. Install dependencies
pip install -r requirements.txt
cd dids-dashboard && npm install && cd ..

# 4. Download pre-trained models
python scripts/download_models.py

# 5. Start services
docker-compose up -d

# 6. Verify deployment
./scripts/health_check.sh
```

### Access Points

```
Dashboard:          http://localhost:3000
API:                http://localhost:5000
Grafana:            http://localhost:3002  (admin/admin)
Prometheus:         http://localhost:9090
MongoDB Express:    http://localhost:8081
```

## Docker Compose Deployment

### Configuration

```yaml
# docker-compose.yml (excerpt)
version: '3.8'

services:
  # Core services
  traffic-capture:
    build: ./traffic-capture
    environment:
      - CAPTURE_INTERFACE=eth0
      - REDIS_HOST=redis
    cap_add:
      - NET_ADMIN
      - NET_RAW
    network_mode: host

  anomaly-detection:
    build: ./anomaly-detection
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2'
          memory: 4G

  rl-agent:
    build: ./rl_module
    environment:
      - MODEL_PATH=/models/double_dqn_final.keras
      - CONFIDENCE_THRESHOLD=0.85

  dashboard:
    build: ./dids-dashboard
    ports:
      - "3000:3000"
    environment:
      - MONGODB_URI=mongodb://mongodb:27017/dids
      - REDIS_URL=redis://redis:6379
```

### Deployment Steps

```bash
# 1. Configure environment
cat > .env <<EOF
# Database
MONGODB_PASSWORD=<secure-password>
POSTGRES_PASSWORD=<secure-password>

# Security
SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
JWT_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

# Network
CAPTURE_INTERFACE=eth0
LOG_LEVEL=INFO
EOF

# 2. Build images
docker-compose build

# 3. Start services
docker-compose up -d

# 4. Check logs
docker-compose logs -f

# 5. Run migrations
docker-compose exec dashboard python manage.py db upgrade

# 6. Create admin user
docker-compose exec dashboard python scripts/create_admin.py
```

### Scaling Services

```bash
# Scale anomaly detection
docker-compose up -d --scale anomaly-detection=4

# Scale RL agent
docker-compose up -d --scale rl-agent=2
```

## Kubernetes Deployment

### Cluster Setup

```bash
# Create namespace
kubectl create namespace dids

# Set context
kubectl config set-context --current --namespace=dids
```

### Deploy Infrastructure

```bash
# 1. Install cert-manager (for TLS)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# 2. Deploy MongoDB
helm install mongodb bitnami/mongodb \
  --set auth.rootPassword=<secure-password> \
  --set architecture=replicaset \
  --set replicaCount=3

# 3. Deploy Redis
helm install redis bitnami/redis \
  --set auth.password=<secure-password> \
  --set master.persistence.size=10Gi

# 4. Deploy RabbitMQ
helm install rabbitmq bitnami/rabbitmq \
  --set auth.username=admin \
  --set auth.password=<secure-password>
```

### Deploy DIDS Services

```bash
# Apply configurations
kubectl apply -f k8s/production/

# Verify deployments
kubectl get deployments
kubectl get pods
kubectl get services
```

### Example Kubernetes Manifests

```yaml
# k8s/production/anomaly-detection.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: anomaly-detection
spec:
  replicas: 4
  selector:
    matchLabels:
      app: anomaly-detection
  template:
    metadata:
      labels:
        app: anomaly-detection
    spec:
      containers:
      - name: anomaly-detection
        image: dids/anomaly-detection:latest
        resources:
          requests:
            cpu: "1"
            memory: "2Gi"
          limits:
            cpu: "2"
            memory: "4Gi"
        env:
        - name: REDIS_HOST
          value: redis-master
        - name: MODEL_PATH
          value: /models/anomaly_detection.keras
        livenessProbe:
          httpGet:
            path: /health
            port: 5001
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 5001
          initialDelaySeconds: 10
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: anomaly-detection
spec:
  selector:
    app: anomaly-detection
  ports:
  - port: 5001
    targetPort: 5001
  type: ClusterIP

---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: anomaly-detection-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: anomaly-detection
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

## Azure Cloud Deployment

### Infrastructure Provisioning with Terraform

```bash
# Navigate to terraform directory
cd terraform

# Initialize Terraform
terraform init

# Plan deployment
terraform plan -out=tfplan

# Apply infrastructure
terraform apply tfplan
```

### Terraform Configuration

```hcl
# terraform/main.tf
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "dids" {
  name     = "rg-dids-prod"
  location = "East US"
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "aks-dids-prod"
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  dns_prefix          = "dids"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D8s_v3"
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
  }
}

resource "azurerm_container_registry" "acr" {
  name                = "acrdidsprod"
  resource_group_name = azurerm_resource_group.dids.name
  location            = azurerm_resource_group.dids.location
  sku                 = "Premium"
  admin_enabled       = true
}

resource "azurerm_key_vault" "kv" {
  name                = "kv-dids-prod"
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
}
```

### Deploy to AKS

```bash
# Get AKS credentials
az aks get-credentials \
  --resource-group rg-dids-prod \
  --name aks-dids-prod

# Configure Azure Container Registry
az acr login --name acrdidsprod

# Build and push images
docker build -t acrdidsprod.azurecr.io/dids-dashboard:latest ./dids-dashboard
docker push acrdidsprod.azurecr.io/dids-dashboard:latest

# Deploy to AKS
kubectl apply -f k8s/production/
```

## Production Best Practices

### 1. Security Hardening

```bash
# Enable network policies
kubectl apply -f k8s/security/network-policies.yaml

# Configure RBAC
kubectl apply -f k8s/security/rbac.yaml

# Enable pod security policies
kubectl apply -f k8s/security/pod-security-policy.yaml

# Use secrets management
kubectl create secret generic dids-secrets \
  --from-literal=mongodb-password=<password> \
  --from-literal=jwt-secret=<secret>
```

### 2. High Availability

```yaml
# Deploy with anti-affinity
apiVersion: apps/v1
kind: Deployment
metadata:
  name: anomaly-detection
spec:
  replicas: 4
  template:
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - anomaly-detection
            topologyKey: kubernetes.io/hostname
```

### 3. Resource Management

```yaml
# Configure resource quotas
apiVersion: v1
kind: ResourceQuota
metadata:
  name: dids-quota
spec:
  hard:
    requests.cpu: "50"
    requests.memory: 100Gi
    limits.cpu: "100"
    limits.memory: 200Gi
```

### 4. Backup Strategy

```bash
# Automated MongoDB backups
kubectl apply -f k8s/cronjobs/mongodb-backup.yaml

# Backup script
cat > backup-mongodb.sh <<'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
mongodump --uri="mongodb://mongodb:27017" --out="/backups/${DATE}"
az storage blob upload-batch \
  --destination backups \
  --source "/backups/${DATE}"
EOF
```

## Monitoring and Operations

### Prometheus and Grafana

```bash
# Install monitoring stack
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set grafana.adminPassword=<password>

# Access Grafana
kubectl port-forward -n monitoring svc/prometheus-grafana 3002:80
```

### Custom Dashboards

Import pre-built Grafana dashboards:
- `monitoring/grafana/dids-system-overview.json`
- `monitoring/grafana/dids-ml-performance.json`
- `monitoring/grafana/dids-security-alerts.json`

### Log Aggregation

```bash
# Install ELK stack
helm install elasticsearch elastic/elasticsearch
helm install kibana elastic/kibana
helm install filebeat elastic/filebeat
```

## Troubleshooting

### Common Issues

**Issue: Pods failing to start**
```bash
# Check pod status
kubectl describe pod <pod-name>

# Check logs
kubectl logs <pod-name> --previous

# Common fixes:
# 1. Check resource limits
# 2. Verify secrets exist
# 3. Check image pull permissions
```

**Issue: High memory usage**
```bash
# Check resource usage
kubectl top pods

# Scale down if needed
kubectl scale deployment anomaly-detection --replicas=2

# Check for memory leaks
kubectl exec -it <pod-name> -- top
```

**Issue: Network connectivity**
```bash
# Test service connectivity
kubectl run -it --rm debug --image=busybox --restart=Never -- sh
# Inside pod:
nc -zv anomaly-detection 5001

# Check network policies
kubectl get networkpolicies
```

### Health Checks

```bash
# Check all services
./scripts/health_check.sh

# Manual health checks
curl http://localhost:5001/health  # Anomaly detection
curl http://localhost:5002/health  # RL agent
curl http://localhost:5003/health  # Alert service
```

### Performance Tuning

```yaml
# Optimize pod resources based on metrics
resources:
  requests:
    cpu: "500m"
    memory: "1Gi"
  limits:
    cpu: "2000m"
    memory: "4Gi"

# Enable CPU pinning
resources:
  requests:
    cpu: "2"
  limits:
    cpu: "2"
```

## Deployment Checklist

### Pre-Deployment

- [ ] Review and update configuration files
- [ ] Test in staging environment
- [ ] Backup existing data
- [ ] Review security settings
- [ ] Verify SSL certificates
- [ ] Check resource quotas
- [ ] Update documentation

### Deployment

- [ ] Deploy infrastructure (Terraform)
- [ ] Deploy databases
- [ ] Deploy application services
- [ ] Configure load balancers
- [ ] Set up monitoring
- [ ] Configure backups
- [ ] Run smoke tests

### Post-Deployment

- [ ] Verify all services running
- [ ] Check logs for errors
- [ ] Monitor resource usage
- [ ] Test critical workflows
- [ ] Update DNS records (if needed)
- [ ] Notify stakeholders
- [ ] Document deployment

## Rollback Procedure

```bash
# Rollback Kubernetes deployment
kubectl rollout undo deployment/anomaly-detection

# Rollback to specific revision
kubectl rollout undo deployment/anomaly-detection --to-revision=2

# Check rollout status
kubectl rollout status deployment/anomaly-detection
```

---

**Last Updated**: 2025-01-20
**Maintained By**: DIDS DevOps Team

For detailed architecture information, see [ARCHITECTURE.md](ARCHITECTURE.md).
For security considerations, see [SECURITY.md](../SECURITY.md).
