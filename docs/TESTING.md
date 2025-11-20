# Testing Strategy and Infrastructure

## Overview

This document outlines the comprehensive testing strategy for the Deep Intrusion Detection System (DIDS). Testing is critical for ensuring reliability, security, and performance of our AI-powered network security solution.

## Table of Contents

1. [Testing Philosophy](#testing-philosophy)
2. [Test Architecture](#test-architecture)
3. [Unit Testing](#unit-testing)
4. [Integration Testing](#integration-testing)
5. [End-to-End Testing](#end-to-end-testing)
6. [ML Model Testing](#ml-model-testing)
7. [RL Agent Testing](#rl-agent-testing)
8. [Performance Testing](#performance-testing)
9. [Security Testing](#security-testing)
10. [Continuous Integration](#continuous-integration)
11. [Test Data Management](#test-data-management)
12. [Running Tests](#running-tests)

## Testing Philosophy

Our testing strategy follows these principles:

- **Test Pyramid**: Heavy unit tests, moderate integration tests, light E2E tests
- **Shift Left**: Catch bugs early in development
- **Automation First**: All tests should be automated and run in CI/CD
- **Real-World Scenarios**: Use realistic network traffic patterns
- **ML-Specific Testing**: Validate model accuracy, fairness, and robustness

```
         /\
        /  \       E2E Tests (10%)
       /____\      - Full system workflows
      /      \     - User scenarios
     /________\    Integration Tests (30%)
    /          \   - Service interactions
   /____________\  - API contracts
  /              \ Unit Tests (60%)
 /________________\- Individual functions
                   - Model components
```

## Test Architecture

### Directory Structure

```
fyp/
├── tests/                          # Root test directory
│   ├── unit/                       # Unit tests
│   │   ├── test_anomaly_detection.py
│   │   ├── test_rl_agent.py
│   │   ├── test_traffic_capture.py
│   │   └── test_dashboard_api.py
│   ├── integration/                # Integration tests
│   │   ├── test_detection_pipeline.py
│   │   ├── test_alert_flow.py
│   │   └── test_microservices.py
│   ├── e2e/                        # End-to-end tests
│   │   ├── test_complete_workflow.py
│   │   └── test_user_scenarios.py
│   ├── performance/                # Performance tests
│   │   ├── test_load.py
│   │   └── test_throughput.py
│   ├── security/                   # Security tests
│   │   ├── test_auth.py
│   │   └── test_injection.py
│   ├── fixtures/                   # Test fixtures
│   │   ├── sample_traffic.pcap
│   │   └── mock_alerts.json
│   └── conftest.py                 # Pytest configuration
├── rl_module/tests/                # RL-specific tests
│   ├── test_dqn_agent.py
│   ├── test_environment.py
│   └── test_training.py
├── ml-training/tests/              # ML-specific tests
│   ├── test_model_accuracy.py
│   └── test_preprocessing.py
└── docker-compose.test.yml         # Test environment
```

## Unit Testing

### Python Services (pytest)

**Framework**: pytest, unittest.mock

**Coverage Target**: >80% code coverage

#### Example: Testing RL Agent

```python
# rl_module/tests/test_dqn_agent.py
import pytest
import numpy as np
from agents.dqn_agent import DoubleDQNAgent

class TestDoubleDQNAgent:
    @pytest.fixture
    def agent(self):
        """Create agent for testing"""
        return DoubleDQNAgent(
            state_size=42,
            action_size=3,
            learning_rate=0.001
        )

    def test_agent_initialization(self, agent):
        """Test agent initializes correctly"""
        assert agent.state_size == 42
        assert agent.action_size == 3
        assert agent.epsilon == 1.0
        assert agent.memory.maxlen == 10000

    def test_remember(self, agent):
        """Test experience replay memory"""
        state = np.random.rand(42)
        next_state = np.random.rand(42)
        agent.remember(state, 0, 1.0, next_state, False)

        assert len(agent.memory) == 1

    def test_act_exploration(self, agent):
        """Test epsilon-greedy exploration"""
        agent.epsilon = 1.0  # Always explore
        state = np.random.rand(42)

        actions = [agent.act(state) for _ in range(100)]
        # Should have variety of actions
        assert len(set(actions)) > 1

    def test_act_exploitation(self, agent):
        """Test exploitation mode"""
        agent.epsilon = 0.0  # Always exploit
        state = np.ones(42)  # Deterministic state

        action1 = agent.act(state)
        action2 = agent.act(state)
        # Should be consistent
        assert action1 == action2

    def test_fail_safe_mode(self, agent):
        """Test fail-safe behavior on low confidence"""
        state = np.random.rand(42)
        action, confidence = agent.act_with_confidence(state)

        if confidence < 0.85:
            assert action == 1  # ALERT action
```

#### Example: Testing Traffic Capture

```python
# tests/unit/test_traffic_capture.py
import pytest
from unittest.mock import Mock, patch
from traffic_capture.capture import PacketCapture

class TestPacketCapture:
    @pytest.fixture
    def capture(self):
        return PacketCapture(interface='lo', filter='tcp')

    def test_initialization(self, capture):
        """Test capture initializes correctly"""
        assert capture.interface == 'lo'
        assert capture.filter == 'tcp'
        assert capture.is_running == False

    @patch('scapy.all.sniff')
    def test_start_capture(self, mock_sniff, capture):
        """Test packet capture starts"""
        capture.start()

        assert capture.is_running == True
        mock_sniff.assert_called_once()

    def test_extract_features(self, capture):
        """Test feature extraction from packet"""
        mock_packet = Mock()
        mock_packet.time = 1234567890
        mock_packet.len = 1500
        mock_packet.haslayer.return_value = True

        features = capture.extract_features(mock_packet)

        assert 'timestamp' in features
        assert 'length' in features
        assert features['length'] == 1500
```

#### Example: Testing API Endpoints

```python
# tests/unit/test_dashboard_api.py
import pytest
from dids_dashboard.app import create_app

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        yield client

@pytest.fixture
def auth_headers(client):
    """Get authentication headers"""
    response = client.post('/api/auth/login', json={
        'email': 'admin@test.com',
        'password': 'testpass123'
    })
    token = response.json['token']
    return {'Authorization': f'Bearer {token}'}

def test_get_alerts_unauthorized(client):
    """Test alerts endpoint requires auth"""
    response = client.get('/api/alerts')
    assert response.status_code == 401

def test_get_alerts_authorized(client, auth_headers):
    """Test alerts endpoint with auth"""
    response = client.get('/api/alerts', headers=auth_headers)
    assert response.status_code == 200
    assert 'alerts' in response.json

def test_acknowledge_alert(client, auth_headers):
    """Test alert acknowledgment"""
    alert_id = "test_alert_123"
    response = client.post(
        f'/api/alerts/{alert_id}/acknowledge',
        headers=auth_headers,
        json={'notes': 'False positive'}
    )
    assert response.status_code == 200
```

### JavaScript/TypeScript (Jest)

**Framework**: Jest, React Testing Library

**Coverage Target**: >75% code coverage

```javascript
// dids-dashboard/src/components/__tests__/AlertCard.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import AlertCard from '../AlertCard';

describe('AlertCard', () => {
  const mockAlert = {
    id: '123',
    severity: 'high',
    title: 'DDoS Attack Detected',
    timestamp: '2025-01-20T12:00:00Z',
    status: 'active'
  };

  it('renders alert information', () => {
    render(<AlertCard alert={mockAlert} />);

    expect(screen.getByText('DDoS Attack Detected')).toBeInTheDocument();
    expect(screen.getByText('high')).toBeInTheDocument();
  });

  it('calls onAcknowledge when button clicked', () => {
    const mockAcknowledge = jest.fn();
    render(
      <AlertCard alert={mockAlert} onAcknowledge={mockAcknowledge} />
    );

    fireEvent.click(screen.getByText('Acknowledge'));
    expect(mockAcknowledge).toHaveBeenCalledWith('123');
  });

  it('shows severity badge with correct color', () => {
    const { container } = render(<AlertCard alert={mockAlert} />);
    const badge = container.querySelector('.severity-badge');

    expect(badge).toHaveClass('severity-high');
  });
});
```

## Integration Testing

### Service-to-Service Communication

```python
# tests/integration/test_detection_pipeline.py
import pytest
import redis
import json
from time import sleep

@pytest.fixture
def redis_client():
    """Connect to test Redis instance"""
    client = redis.Redis(host='localhost', port=6379, db=1)
    yield client
    client.flushdb()  # Clean up

def test_traffic_to_anomaly_detection_flow(redis_client):
    """Test traffic capture publishes to anomaly detection"""
    # Simulate traffic capture publishing
    packet_data = {
        'timestamp': 1234567890,
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'protocol': 'TCP',
        'length': 1500
    }

    redis_client.publish('network_traffic', json.dumps(packet_data))

    # Check anomaly detection received it
    # (In real test, would check anomaly service logs or database)
    sleep(0.5)

    # Verify packet was processed
    # ...

def test_detection_to_rl_flow():
    """Test anomaly detection triggers RL agent"""
    import requests

    # Send anomaly to RL agent
    detection = {
        'features': [0.1, 0.2, 0.3, ...],
        'confidence': 0.95,
        'attack_type': 'DDoS'
    }

    response = requests.post(
        'http://localhost:5002/predict',
        json=detection,
        timeout=5
    )

    assert response.status_code == 200
    assert 'action' in response.json()
    assert response.json()['action'] in ['allow', 'alert', 'quarantine']
```

### Database Integration

```python
# tests/integration/test_mongodb.py
import pytest
from pymongo import MongoClient
from datetime import datetime

@pytest.fixture
def db():
    """Connect to test MongoDB"""
    client = MongoClient('mongodb://localhost:27017/')
    db = client['dids_test']
    yield db
    client.drop_database('dids_test')

def test_alert_insertion(db):
    """Test alert is stored correctly"""
    alert = {
        'timestamp': datetime.utcnow(),
        'severity': 'high',
        'attack_type': 'Port Scan',
        'src_ip': '192.168.1.100',
        'status': 'active'
    }

    result = db.alerts.insert_one(alert)
    assert result.inserted_id is not None

    # Verify retrieval
    retrieved = db.alerts.find_one({'_id': result.inserted_id})
    assert retrieved['attack_type'] == 'Port Scan'

def test_alert_query_performance(db):
    """Test alert queries are fast"""
    # Insert 1000 test alerts
    alerts = [
        {
            'timestamp': datetime.utcnow(),
            'severity': 'high' if i % 3 == 0 else 'medium',
            'attack_type': 'DDoS',
            'src_ip': f'192.168.1.{i % 255}'
        }
        for i in range(1000)
    ]
    db.alerts.insert_many(alerts)

    # Query should be fast
    import time
    start = time.time()
    results = list(db.alerts.find({'severity': 'high'}).limit(50))
    duration = time.time() - start

    assert len(results) <= 50
    assert duration < 0.1  # Should be under 100ms
```

## End-to-End Testing

### Complete Workflow Test

```python
# tests/e2e/test_complete_workflow.py
import pytest
import requests
import docker
from time import sleep

@pytest.fixture(scope='module')
def docker_compose():
    """Start all services with docker-compose"""
    client = docker.from_env()
    # Start services
    os.system('docker-compose -f docker-compose.test.yml up -d')
    sleep(30)  # Wait for services to start

    yield client

    # Teardown
    os.system('docker-compose -f docker-compose.test.yml down')

def test_full_detection_workflow(docker_compose):
    """Test complete detection workflow end-to-end"""

    # 1. Inject test traffic
    inject_malicious_traffic()

    # 2. Wait for detection
    sleep(5)

    # 3. Check alert was created
    response = requests.get('http://localhost:3000/api/alerts')
    assert response.status_code == 200
    alerts = response.json()['alerts']
    assert len(alerts) > 0

    # 4. Verify alert has correct properties
    alert = alerts[0]
    assert alert['severity'] in ['low', 'medium', 'high', 'critical']
    assert 'timestamp' in alert
    assert 'action_taken' in alert

    # 5. Acknowledge alert
    response = requests.post(
        f'http://localhost:3000/api/alerts/{alert["id"]}/acknowledge',
        json={'notes': 'Test acknowledgment'}
    )
    assert response.status_code == 200
```

## ML Model Testing

### Model Accuracy Testing

```python
# ml-training/tests/test_model_accuracy.py
import pytest
import numpy as np
import tensorflow as tf
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

@pytest.fixture
def test_dataset():
    """Load test dataset"""
    X_test = np.load('ml-training/data/preprocessed/X_test.npy')
    y_test = np.load('ml-training/data/preprocessed/y_test.npy')
    return X_test, y_test

@pytest.fixture
def anomaly_model():
    """Load trained model"""
    return tf.keras.models.load_model('dids-dashboard/model/anomaly_detection.keras')

def test_model_accuracy(anomaly_model, test_dataset):
    """Test model meets accuracy threshold"""
    X_test, y_test = test_dataset

    predictions = anomaly_model.predict(X_test)
    y_pred = (predictions > 0.5).astype(int).flatten()

    accuracy = accuracy_score(y_test, y_pred)

    assert accuracy >= 0.95, f"Model accuracy {accuracy} below threshold"

def test_model_f1_score(anomaly_model, test_dataset):
    """Test model F1 score"""
    X_test, y_test = test_dataset

    predictions = anomaly_model.predict(X_test)
    y_pred = (predictions > 0.5).astype(int).flatten()

    f1 = f1_score(y_test, y_pred)

    assert f1 >= 0.90, f"F1 score {f1} below threshold"

def test_false_positive_rate(anomaly_model, test_dataset):
    """Test false positive rate is acceptable"""
    X_test, y_test = test_dataset

    predictions = anomaly_model.predict(X_test)
    y_pred = (predictions > 0.5).astype(int).flatten()

    # Calculate FPR
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn)

    assert fpr <= 0.02, f"False positive rate {fpr} too high"

def test_model_inference_time(anomaly_model):
    """Test model inference is fast enough"""
    import time

    # Single sample
    sample = np.random.rand(1, 42)

    start = time.time()
    prediction = anomaly_model.predict(sample, verbose=0)
    duration = time.time() - start

    # Should predict in under 50ms
    assert duration < 0.05, f"Inference time {duration}s too slow"

def test_batch_inference_time(anomaly_model):
    """Test batch inference throughput"""
    import time

    # Batch of 100 samples
    batch = np.random.rand(100, 42)

    start = time.time()
    predictions = anomaly_model.predict(batch, verbose=0)
    duration = time.time() - start

    # Should handle 100 samples in under 500ms
    assert duration < 0.5, f"Batch inference time {duration}s too slow"
```

### Model Robustness Testing

```python
# ml-training/tests/test_model_robustness.py
def test_model_handles_edge_cases(anomaly_model):
    """Test model handles edge cases gracefully"""

    # Test with all zeros
    zeros = np.zeros((1, 42))
    pred_zeros = anomaly_model.predict(zeros, verbose=0)
    assert 0 <= pred_zeros[0][0] <= 1

    # Test with all ones
    ones = np.ones((1, 42))
    pred_ones = anomaly_model.predict(ones, verbose=0)
    assert 0 <= pred_ones[0][0] <= 1

    # Test with extreme values
    extreme = np.ones((1, 42)) * 1000
    pred_extreme = anomaly_model.predict(extreme, verbose=0)
    assert 0 <= pred_extreme[0][0] <= 1

def test_model_consistency(anomaly_model):
    """Test model produces consistent results"""
    sample = np.random.rand(1, 42)

    # Multiple predictions should be identical
    pred1 = anomaly_model.predict(sample, verbose=0)[0][0]
    pred2 = anomaly_model.predict(sample, verbose=0)[0][0]
    pred3 = anomaly_model.predict(sample, verbose=0)[0][0]

    assert pred1 == pred2 == pred3
```

## RL Agent Testing

### Agent Behavior Testing

```python
# rl_module/tests/test_dqn_behavior.py
import pytest
import numpy as np
from agents.dqn_agent import DoubleDQNAgent
from environments.ids_environment import IDSEnvironment

def test_rl_agent_decision_quality():
    """Test RL agent makes sensible decisions"""
    agent = DoubleDQNAgent.load('dids-dashboard/model/double_dqn_final.keras')

    # Benign traffic - should ALLOW
    benign_state = create_benign_state()
    action = agent.act(benign_state)
    assert action == 0  # ALLOW

    # Obvious attack - should QUARANTINE
    attack_state = create_attack_state()
    action = agent.act(attack_state)
    assert action == 2  # QUARANTINE

def test_rl_agent_fail_safe():
    """Test fail-safe mode activates on low confidence"""
    agent = DoubleDQNAgent.load('dids-dashboard/model/double_dqn_final.keras')

    # Ambiguous traffic
    ambiguous_state = create_ambiguous_state()
    action, confidence = agent.act_with_confidence(ambiguous_state)

    if confidence < 0.85:
        assert action == 1  # ALERT (fail-safe)

def test_rl_training_convergence():
    """Test RL agent trains and converges"""
    env = IDSEnvironment()
    agent = DoubleDQNAgent(state_size=42, action_size=3)

    rewards = []
    for episode in range(10):
        state = env.reset()
        episode_reward = 0

        for step in range(100):
            action = agent.act(state)
            next_state, reward, done, _ = env.step(action)
            agent.remember(state, action, reward, next_state, done)

            episode_reward += reward
            state = next_state

            if done:
                break

        rewards.append(episode_reward)
        agent.replay(32)

    # Rewards should improve
    assert np.mean(rewards[-3:]) > np.mean(rewards[:3])

def test_rl_action_distribution():
    """Test RL agent action distribution is reasonable"""
    agent = DoubleDQNAgent.load('dids-dashboard/model/double_dqn_final.keras')

    # Run 1000 random states
    actions = []
    for _ in range(1000):
        state = np.random.rand(42)
        action = agent.act(state)
        actions.append(action)

    # Count actions
    allow_pct = actions.count(0) / len(actions)
    alert_pct = actions.count(1) / len(actions)
    quarantine_pct = actions.count(2) / len(actions)

    # Should have reasonable distribution (not all one action)
    assert allow_pct > 0.1
    assert alert_pct > 0.05
    assert quarantine_pct > 0.05
```

## Performance Testing

### Load Testing

```python
# tests/performance/test_load.py
import pytest
from locust import HttpUser, task, between

class DIDSUser(HttpUser):
    wait_time = between(1, 3)

    @task(3)
    def view_dashboard(self):
        """Most common task - view dashboard"""
        self.client.get('/dashboard')

    @task(2)
    def view_alerts(self):
        """View alerts"""
        self.client.get('/api/alerts')

    @task(1)
    def acknowledge_alert(self):
        """Acknowledge random alert"""
        response = self.client.get('/api/alerts')
        alerts = response.json().get('alerts', [])
        if alerts:
            alert_id = alerts[0]['id']
            self.client.post(f'/api/alerts/{alert_id}/acknowledge')

# Run with: locust -f tests/performance/test_load.py --host=http://localhost:3000
```

### Throughput Testing

```python
# tests/performance/test_throughput.py
import time
import numpy as np

def test_packet_processing_throughput():
    """Test system can handle expected packet rate"""
    from traffic_capture.capture import PacketProcessor

    processor = PacketProcessor()

    # Simulate 10,000 packets
    packets = [generate_random_packet() for _ in range(10000)]

    start = time.time()
    for packet in packets:
        processor.process(packet)
    duration = time.time() - start

    pps = 10000 / duration

    # Should handle at least 5000 packets per second
    assert pps >= 5000, f"Throughput {pps} pps below target"

def test_detection_latency():
    """Test end-to-end detection latency"""
    import requests

    latencies = []

    for _ in range(100):
        packet_data = generate_random_packet()

        start = time.time()
        response = requests.post(
            'http://localhost:5001/detect',
            json=packet_data
        )
        latency = time.time() - start

        latencies.append(latency)

    avg_latency = np.mean(latencies)
    p95_latency = np.percentile(latencies, 95)

    # Average should be under 50ms, P95 under 100ms
    assert avg_latency < 0.05, f"Avg latency {avg_latency}s too high"
    assert p95_latency < 0.1, f"P95 latency {p95_latency}s too high"
```

## Security Testing

### Authentication Testing

```python
# tests/security/test_auth.py
import pytest
import requests

def test_login_with_valid_credentials():
    """Test login succeeds with valid credentials"""
    response = requests.post('http://localhost:3000/api/auth/login', json={
        'email': 'admin@test.com',
        'password': 'ValidPass123!'
    })
    assert response.status_code == 200
    assert 'token' in response.json()

def test_login_with_invalid_password():
    """Test login fails with wrong password"""
    response = requests.post('http://localhost:3000/api/auth/login', json={
        'email': 'admin@test.com',
        'password': 'WrongPassword'
    })
    assert response.status_code == 401

def test_weak_password_rejected():
    """Test weak passwords are rejected"""
    response = requests.post('http://localhost:3000/api/auth/register', json={
        'email': 'new@test.com',
        'password': 'weak'
    })
    assert response.status_code == 400
    assert 'password' in response.json()['errors']

def test_brute_force_protection():
    """Test brute force protection kicks in"""
    # Try 10 failed logins
    for _ in range(10):
        requests.post('http://localhost:3000/api/auth/login', json={
            'email': 'admin@test.com',
            'password': 'wrong'
        })

    # 11th attempt should be rate limited
    response = requests.post('http://localhost:3000/api/auth/login', json={
        'email': 'admin@test.com',
        'password': 'wrong'
    })
    assert response.status_code == 429  # Too Many Requests
```

### Injection Testing

```python
# tests/security/test_injection.py
def test_sql_injection_protection():
    """Test SQL injection attempts are blocked"""
    malicious_input = "'; DROP TABLE users; --"

    response = requests.get(
        'http://localhost:3000/api/search',
        params={'query': malicious_input}
    )

    # Should not execute malicious SQL
    assert response.status_code in [200, 400]
    # Database should still exist
    assert check_database_intact()

def test_xss_protection():
    """Test XSS attempts are sanitized"""
    xss_payload = '<script>alert("XSS")</script>'

    response = requests.post('http://localhost:3000/api/alerts/comment', json={
        'alert_id': '123',
        'comment': xss_payload
    })

    # Retrieve comment
    response = requests.get('http://localhost:3000/api/alerts/123')
    comment = response.json()['comments'][0]

    # Should be escaped
    assert '<script>' not in comment
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest pytest-cov

      - name: Run unit tests
        run: |
          pytest tests/unit/ -v --cov=. --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  integration-tests:
    runs-on: ubuntu-latest
    services:
      mongodb:
        image: mongo:7
        ports:
          - 27017:27017
      redis:
        image: redis:7
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v3

      - name: Run integration tests
        run: |
          pytest tests/integration/ -v

  ml-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Download test models
        run: |
          # Download pre-trained models for testing
          python scripts/download_models.py

      - name: Test ML models
        run: |
          pytest ml-training/tests/ -v
          pytest rl_module/tests/ -v

  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run Bandit security scan
        run: |
          pip install bandit
          bandit -r . -f json -o bandit-report.json

      - name: Run Trivy vulnerability scan
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          severity: 'CRITICAL,HIGH'
```

## Test Data Management

### Fixture Data

```python
# tests/fixtures/traffic_generator.py
import numpy as np

def create_benign_state():
    """Create benign traffic state"""
    return np.array([
        0.1,  # Low packet rate
        64,   # Small packet size
        0,    # No SYN flood indicators
        0,    # No port scan indicators
        # ... 38 more features
    ])

def create_attack_state(attack_type='ddos'):
    """Create attack traffic state"""
    if attack_type == 'ddos':
        return np.array([
            10.0,  # High packet rate
            1500,  # Large packet size
            1,     # SYN flood indicator
            0,     # No port scan
            # ... 38 more features
        ])
    elif attack_type == 'port_scan':
        return np.array([
            5.0,   # Moderate packet rate
            64,    # Small packets
            0,     # No SYN flood
            1,     # Port scan indicator
            # ... 38 more features
        ])

def generate_random_packet():
    """Generate random packet for load testing"""
    return {
        'timestamp': time.time(),
        'src_ip': f'192.168.1.{np.random.randint(1, 255)}',
        'dst_ip': f'10.0.0.{np.random.randint(1, 255)}',
        'protocol': np.random.choice(['TCP', 'UDP', 'ICMP']),
        'length': np.random.randint(64, 1500)
    }
```

### Test Database Seeding

```python
# tests/fixtures/seed_test_db.py
from pymongo import MongoClient
from datetime import datetime, timedelta

def seed_test_database():
    """Seed test database with sample data"""
    client = MongoClient('mongodb://localhost:27017/')
    db = client['dids_test']

    # Clear existing data
    db.alerts.delete_many({})
    db.users.delete_many({})

    # Create test users
    db.users.insert_many([
        {
            'email': 'admin@test.com',
            'password_hash': hash_password('AdminPass123!'),
            'role': 'admin'
        },
        {
            'email': 'analyst@test.com',
            'password_hash': hash_password('AnalystPass123!'),
            'role': 'analyst'
        }
    ])

    # Create test alerts
    base_time = datetime.utcnow()
    alerts = []
    for i in range(100):
        alerts.append({
            'timestamp': base_time - timedelta(hours=i),
            'severity': np.random.choice(['low', 'medium', 'high']),
            'attack_type': np.random.choice(['DDoS', 'Port Scan', 'Brute Force']),
            'src_ip': f'192.168.1.{i % 255}',
            'status': 'active' if i < 10 else 'acknowledged'
        })

    db.alerts.insert_many(alerts)
```

## Running Tests

### Local Testing

```bash
# Run all unit tests
pytest tests/unit/ -v

# Run with coverage
pytest tests/unit/ --cov=. --cov-report=html

# Run specific test file
pytest tests/unit/test_dqn_agent.py -v

# Run specific test
pytest tests/unit/test_dqn_agent.py::TestDoubleDQNAgent::test_agent_initialization -v

# Run integration tests (requires services)
docker-compose -f docker-compose.test.yml up -d
pytest tests/integration/ -v
docker-compose -f docker-compose.test.yml down

# Run performance tests
pytest tests/performance/ -v

# Run security tests
pytest tests/security/ -v
```

### JavaScript Tests

```bash
cd dids-dashboard

# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Run in watch mode
npm test -- --watch

# Run specific test file
npm test -- AlertCard.test.tsx
```

### Load Testing

```bash
# Install Locust
pip install locust

# Run load test
locust -f tests/performance/test_load.py --host=http://localhost:3000

# Headless mode with specific parameters
locust -f tests/performance/test_load.py \
  --host=http://localhost:3000 \
  --users 100 \
  --spawn-rate 10 \
  --run-time 5m \
  --headless
```

## Test Coverage Goals

| Component | Target Coverage | Current |
|-----------|----------------|---------|
| RL Module | >85% | TBD |
| Anomaly Detection | >80% | TBD |
| Dashboard Backend | >80% | TBD |
| Dashboard Frontend | >75% | TBD |
| Microservices | >80% | TBD |
| Traffic Capture | >75% | TBD |

## Best Practices

1. **Write Tests First**: Follow TDD when adding new features
2. **Test Edge Cases**: Don't just test the happy path
3. **Mock External Dependencies**: Use mocks for Redis, MongoDB, etc.
4. **Isolate Tests**: Each test should be independent
5. **Fast Tests**: Unit tests should run in milliseconds
6. **Meaningful Names**: Test names should describe what they test
7. **One Assertion Focus**: Each test should verify one behavior
8. **Clean Up**: Always clean up test data in teardown

## Troubleshooting

### Common Issues

**Tests fail due to missing models**:
```bash
# Download pre-trained models
python scripts/download_models.py
```

**Port conflicts in integration tests**:
```bash
# Use different ports in docker-compose.test.yml
# Or stop conflicting services
docker-compose down
```

**Slow tests**:
```bash
# Run only fast tests with markers
pytest -m "not slow" -v

# Or increase timeout
pytest --timeout=300
```

---

**Last Updated**: 2025-01-20
**Maintained By**: DIDS Development Team
