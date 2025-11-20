# Deep Intrusion Detection System (DIDS)

[![CI/CD](https://github.com/100-1824/fyp/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/100-1824/fyp/actions/workflows/ci-cd.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Overview

**Deep Intrusion Detection System (DIDS)** is an advanced, AI-powered network security solution that combines signature-based detection (Suricata), anomaly detection (Deep Learning), and adaptive response (Reinforcement Learning) to provide comprehensive protection for banking and enterprise networks.

### Key Features

- 🛡️ **Multi-Layer Detection**
  - Signature-based detection using Suricata
  - Anomaly detection with Deep Learning models (99% accuracy)
  - Adaptive response using Double DQN RL agent (100% test accuracy)

- 🤖 **AI/ML Integration**
  - Pre-trained CNN/LSTM models for traffic analysis
  - Real-time threat classification
  - Continuous learning and adaptation

- 📊 **Comprehensive Dashboard**
  - Real-time threat visualization
  - Alert management and prioritization
  - System health monitoring

- 🚀 **Cloud-Native Architecture**
  - Microservices-based design
  - Kubernetes-ready deployment
  - Horizontal scaling capabilities

- 🔒 **Enterprise-Ready**
  - Role-based access control (RBAC)
  - Audit logging
  - Compliance reporting

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Network Traffic                          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
        ┌─────────────────┴─────────────────┐
        │                                    │
┌───────▼────────┐              ┌───────────▼──────────┐
│   Suricata     │              │  Traffic Capture     │
│  (Signature)   │              │    (Packet Sniff)    │
└───────┬────────┘              └──────────┬───────────┘
        │                                  │
        │                       ┌──────────▼──────────┐
        │                       │  Anomaly Detection  │
        │                       │   (Deep Learning)   │
        │                       └──────────┬──────────┘
        │                                  │
        └──────────┬───────────────────────┘
                   │
            ┌──────▼─────┐
            │  RL Agent  │
            │  (DQN)     │
            └──────┬─────┘
                   │
        ┌──────────▼──────────┐
        │  Alert Management   │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │     Dashboard       │
        └─────────────────────┘
```

## Performance Metrics

### RL Agent (Double DQN)
- **Accuracy**: 100%
- **F1 Score**: 1.00
- **Action Distribution**:
  - Allow (Benign): 70.01%
  - Quarantine (Attack): 29.99%

### Anomaly Detection Model
- **Accuracy**: 97.3%
- **F1 Score**: 95.4%
- **Detection Rate**: 99.2%
- **False Positive Rate**: <2%

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Kubernetes cluster (optional for production)
- Python 3.11+
- Node.js 18+

### Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/100-1824/fyp.git
   cd fyp
   ```

2. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start all services**
   ```bash
   docker-compose up -d
   ```

4. **Access the dashboard**
   ```
   http://localhost:3000
   ```

### Quick Test of RL Agent

```bash
python rl_module/test_dqn_model.py \
  --model dids-dashboard/model/double_dqn_final.keras \
  --data ml-training/data/preprocessed \
  --samples 10
```

## Project Structure

```
fyp/
├── .github/
│   └── workflows/          # CI/CD pipelines
├── anomaly-detection/      # Anomaly detection service
├── dids-dashboard/         # Web dashboard
│   ├── model/              # Pre-trained models
│   └── ...
├── dids-deployment/        # Deployment configurations
├── k8s/                    # Kubernetes manifests
├── microservices/          # Microservices
│   ├── alert-service/
│   └── threat-intel/
├── ml-training/            # ML model training
├── rl_module/              # Reinforcement Learning
│   ├── agents/             # DQN agents
│   ├── environments/       # RL environments
│   └── tests/              # Unit tests
├── signature-detection/    # Suricata integration
├── terraform/              # Infrastructure as Code
├── traffic-capture/        # Packet capture service
├── docker-compose.yml      # Docker Compose config
└── README.md
```

## Development

### Running Tests

```bash
# RL Module Unit Tests
cd rl_module/tests
python -m unittest discover -v

# Dashboard Tests
cd dids-dashboard
npm test

# Integration Tests
docker-compose -f docker-compose.test.yml up --abort-on-container-exit
```

### Code Quality

```bash
# Python
flake8 .
black .
pylint **/*.py

# JavaScript/TypeScript
cd dids-dashboard
npm run lint
npm run format
```

## Deployment

### Docker Compose (Development/Testing)

```bash
docker-compose up -d
```

### Kubernetes (Production)

```bash
# Apply infrastructure
cd terraform
terraform init
terraform apply

# Deploy to AKS
kubectl apply -f k8s/production/
```

### Azure Deployment

See [DEPLOYMENT.md](docs/DEPLOYMENT.md) for detailed deployment instructions.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password | changeme |
| `REDIS_HOST` | Redis hostname | redis |
| `CAPTURE_INTERFACE` | Network interface for capture | eth0 |
| `RL_FAILSAFE` | Enable RL fail-safe mode | true |
| `LOG_LEVEL` | Logging level | INFO |

See [.env.example](.env.example) for complete list.

## Monitoring

### Grafana Dashboards

Access Grafana at `http://localhost:3002`

Default credentials: `admin` / `admin`

### Prometheus Metrics

- System metrics: `http://localhost:9090`
- Custom metrics endpoints on each service

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Documentation

- [Architecture Guide](docs/ARCHITECTURE.md)
- [API Documentation](docs/API.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [RL Agent Guide](rl_module/README.md)
- [Training Guide](ml-training/README.md)

## Security

- Report security vulnerabilities to: security@example.com
- See [SECURITY.md](SECURITY.md) for security policy

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Suricata for signature-based detection
- TensorFlow/Keras for deep learning capabilities
- React for dashboard interface
- Azure for cloud infrastructure

## Contact

- **Project Lead**: [Your Name]
- **Email**: your.email@example.com
- **GitHub**: [@100-1824](https://github.com/100-1824)

## Citation

If you use this project in your research, please cite:

```bibtex
@misc{dids2025,
  title={Deep Intrusion Detection System: AI-Powered Network Security},
  author={Your Name},
  year={2025},
  publisher={GitHub},
  url={https://github.com/100-1824/fyp}
}
```

---

**⚠️ Disclaimer**: This system is designed for authorized network security testing and monitoring only. Ensure compliance with all applicable laws and regulations.
