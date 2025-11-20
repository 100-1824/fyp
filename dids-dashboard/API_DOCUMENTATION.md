# DIDS Dashboard REST API Documentation

Complete REST API documentation for the Distributed Intrusion Detection System (DIDS) Dashboard.

## Base URL

```
http://localhost:8000/api/v1
```

## Authentication

All API endpoints (except `/docs`) require authentication. The API uses session-based authentication via Flask-Login.

### Login

First, authenticate via the web interface at `/auth/login` or use the authentication API.

## API Endpoints

### Dashboard Overview

#### GET `/dashboard/overview`

Get dashboard overview with key metrics.

**Response:**
```json
{
  "total_packets": 125430,
  "total_threats": 234,
  "threats_blocked": 189,
  "ai_detections": 45,
  "rl_decisions": 234,
  "system_health": "healthy",
  "uptime": "99.9%",
  "last_updated": "2025-11-20T10:30:00"
}
```

---

### Traffic Management

#### POST `/traffic/capture/start`

Start packet capture.

**Response:**
```json
{
  "message": "Packet capture started",
  "status": "active"
}
```

#### POST `/traffic/capture/stop`

Stop packet capture.

**Response:**
```json
{
  "message": "Packet capture stopped",
  "status": "inactive"
}
```

#### GET `/traffic/capture/status`

Get current capture status.

**Response:**
```json
{
  "active": true,
  "buffer_size": 543,
  "total_packets": 125430,
  "protocol_distribution": {
    "TCP": 98234,
    "UDP": 23456,
    "ICMP": 3740
  }
}
```

#### GET `/traffic/recent`

Get recent network traffic.

**Query Parameters:**
- `limit` (optional): Number of packets to return (default: 100, max: 1000)

**Response:**
```json
{
  "packets": [
    {
      "timestamp": "10:30:15.234",
      "source": "192.168.1.100",
      "destination": "8.8.8.8",
      "protocol": "TCP",
      "size": 1024,
      "threat": false
    }
  ],
  "count": 100
}
```

---

### Threat Detection

#### GET `/threats/recent`

Get recent threat detections.

**Query Parameters:**
- `limit` (optional): Number of threats to return (default: 20, max: 100)

**Response:**
```json
{
  "detections": [
    {
      "timestamp": "2025-11-20T10:30:00",
      "source": "192.168.1.50",
      "destination": "10.0.0.1",
      "protocol": "TCP",
      "threat_type": "Port Scan",
      "severity": "high",
      "signature": "ET SCAN Aggressive Port Scan",
      "confidence": 95.0,
      "action": "alert",
      "detector": "signature"
    }
  ],
  "count": 15
}
```

#### POST `/threats/analyze`

Analyze a packet for threats.

**Request Body:**
```json
{
  "source": "192.168.1.100",
  "destination": "8.8.8.8",
  "protocol": "TCP",
  "size": 1024,
  "src_port": 54321,
  "dst_port": 443,
  "syn": 1,
  "ack": 0
}
```

**Response:**
```json
{
  "packet": { ... },
  "detections": [
    {
      "detector": "ai",
      "attack_type": "DDoS",
      "confidence": 87.5,
      "severity": "critical"
    }
  ],
  "rl_decision": {
    "action": "block",
    "confidence": 92.3,
    "reason": "RL agent detected high threat level"
  },
  "final_action": {
    "action": "block",
    "reason": "Critical threat: DDoS",
    "confidence": 92.3
  }
}
```

#### GET `/threats/statistics`

Get threat detection statistics.

**Response:**
```json
{
  "total_threats": 234,
  "by_signature": {
    "ET SCAN Port Scan": 87,
    "ET MALWARE Reverse Shell": 23,
    "ET WEB SQL Injection": 45
  },
  "ai_detections": 79,
  "by_attack_type": {
    "DDoS": 34,
    "PortScan": 25,
    "Web Attack": 20
  },
  "severity_distribution": {
    "critical": 45,
    "high": 120,
    "medium": 60,
    "low": 9
  }
}
```

---

### AI/ML Endpoints

#### GET `/ai/model/info`

Get AI model information.

**Response:**
```json
{
  "model_loaded": true,
  "features_count": 77,
  "classes": [
    "Benign",
    "DDoS",
    "PortScan",
    "Bot",
    "Web Attack",
    "Brute Force"
  ],
  "classes_count": 15
}
```

#### GET `/ai/statistics`

Get AI detection statistics.

**Response:**
```json
{
  "total_predictions": 1543,
  "detections": 234,
  "by_attack_type": {
    "DDoS": 87,
    "PortScan": 65,
    "Web Attack": 45
  },
  "errors": 0
}
```

#### GET `/rl/statistics`

Get RL agent statistics.

**Response:**
```json
{
  "total_decisions": 1543,
  "actions": {
    "allow": 1234,
    "alert": 234,
    "block": 75
  },
  "errors": 0
}
```

---

### System Health

#### GET `/system/health`

Get overall system health.

**Response:**
```json
{
  "status": "healthy",
  "services": {
    "traffic-capture": {
      "status": "healthy",
      "response_time": 0.015
    },
    "signature-detection": {
      "status": "healthy",
      "response_time": 0.012
    },
    "ai-detection": {
      "status": "healthy",
      "response_time": 0.025
    },
    "rl-detection": {
      "status": "healthy",
      "response_time": 0.018
    }
  },
  "healthy_services": 4,
  "total_services": 4,
  "timestamp": "2025-11-20T10:30:00"
}
```

#### GET `/system/services`

Get status of all microservices.

**Response:**
```json
{
  "traffic_capture": {
    "url": "http://localhost:5001",
    "status": "online",
    "info": {
      "service": "traffic-capture",
      "status": "healthy"
    }
  },
  "signature_detection": {
    "url": "http://localhost:5002",
    "status": "online"
  },
  "ai_detection": {
    "url": "http://localhost:5003",
    "status": "online"
  },
  "rl_detection": {
    "url": "http://localhost:5004",
    "status": "online"
  }
}
```

---

### Configuration

#### GET `/config/whitelist`

Get IP whitelist.

**Response:**
```json
{
  "whitelist": [
    "127.0.0.1",
    "192.168.1.1",
    "10.0.0.1"
  ]
}
```

#### POST `/config/whitelist`

Add IP to whitelist (Admin only).

**Request Body:**
```json
{
  "ip": "192.168.1.100"
}
```

**Response:**
```json
{
  "message": "Added 192.168.1.100 to whitelist"
}
```

#### GET `/config/signatures`

Get loaded threat signatures.

**Response:**
```json
{
  "signatures": [
    "ET MALWARE Reverse Shell",
    "ET SCAN Aggressive Port Scan",
    "ET WEB SQL Injection Attempt",
    "ET WEB XSS Attack",
    "ET DNS Excessive Queries"
  ],
  "count": 5
}
```

---

### Reports & Analytics

#### GET `/reports/summary`

Get summary report for specified time period.

**Query Parameters:**
- `hours` (optional): Time period in hours (default: 24)

**Response:**
```json
{
  "time_period": "Last 24 hours",
  "generated_at": "2025-11-20T10:30:00",
  "summary": {
    "total_packets_analyzed": 125430,
    "threats_detected": 234,
    "ai_detections": 79,
    "rl_decisions_made": 234
  },
  "detection_breakdown": {
    "signature_based": {
      "ET SCAN Port Scan": 87
    },
    "ai_based": {
      "DDoS": 34,
      "PortScan": 25
    },
    "rl_actions": {
      "allow": 1234,
      "alert": 234,
      "block": 75
    }
  },
  "system_performance": {
    "services_healthy": true,
    "average_response_time": "5ms",
    "throughput": "1000 packets/sec"
  }
}
```

#### POST `/reports/export`

Export report in specified format.

**Request Body:**
```json
{
  "format": "json"  // json, csv, or pdf
}
```

**Response:**
```json
{
  "format": "json",
  "data": { ... },
  "exported_at": "2025-11-20T10:30:00"
}
```

---

### Alerts & Notifications

#### GET `/alerts/recent`

Get recent security alerts.

**Query Parameters:**
- `limit` (optional): Number of alerts to return (default: 50, max: 200)

**Response:**
```json
{
  "alerts": [
    {
      "id": 1,
      "timestamp": "2025-11-20T10:30:00",
      "severity": "high",
      "type": "Port Scan",
      "source": "192.168.1.50",
      "destination": "10.0.0.1",
      "message": "Port scan detected from 192.168.1.50",
      "action": "alert",
      "read": false
    }
  ],
  "count": 15
}
```

---

### User Management

#### GET `/users/profile`

Get current user profile.

**Response:**
```json
{
  "id": "507f1f77bcf86cd799439011",
  "username": "admin",
  "full_name": "Administrator",
  "email": "admin@dids.local",
  "role": "admin",
  "active": true
}
```

#### PUT `/users/profile`

Update current user profile.

**Request Body:**
```json
{
  "full_name": "John Doe",
  "email": "john@example.com"
}
```

**Response:**
```json
{
  "message": "Profile updated successfully"
}
```

---

### API Documentation

#### GET `/docs`

Get API documentation (this document in JSON format).

**Response:**
```json
{
  "version": "1.0.0",
  "base_url": "/api/v1",
  "endpoints": { ... },
  "authentication": "Session-based (Flask-Login)",
  "response_format": "JSON"
}
```

---

## Response Format

All API responses follow a consistent JSON format.

### Success Response

```json
{
  "data": { ... },
  "message": "Success message (optional)"
}
```

### Error Response

```json
{
  "error": "Error message",
  "code": "ERROR_CODE (optional)"
}
```

## HTTP Status Codes

- `200 OK` - Request successful
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

## Rate Limiting

Currently not implemented. Future versions will include rate limiting.

## Examples

### cURL Examples

**Get dashboard overview:**
```bash
curl -X GET http://localhost:8000/api/v1/dashboard/overview \
  -H "Cookie: session=YOUR_SESSION_COOKIE"
```

**Start packet capture:**
```bash
curl -X POST http://localhost:8000/api/v1/traffic/capture/start \
  -H "Cookie: session=YOUR_SESSION_COOKIE"
```

**Analyze a packet:**
```bash
curl -X POST http://localhost:8000/api/v1/threats/analyze \
  -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION_COOKIE" \
  -d '{
    "source": "192.168.1.100",
    "destination": "8.8.8.8",
    "protocol": "TCP",
    "size": 1024,
    "dst_port": 443
  }'
```

### Python Examples

```python
import requests

# Base URL
BASE_URL = "http://localhost:8000/api/v1"

# Login first (get session cookie)
session = requests.Session()
session.post("http://localhost:8000/auth/login", data={
    "username": "admin",
    "password": "password"
})

# Get dashboard overview
response = session.get(f"{BASE_URL}/dashboard/overview")
data = response.json()
print(f"Total packets: {data['total_packets']}")

# Start packet capture
response = session.post(f"{BASE_URL}/traffic/capture/start")
print(response.json())

# Get recent threats
response = session.get(f"{BASE_URL}/threats/recent?limit=10")
threats = response.json()
print(f"Recent threats: {threats['count']}")
```

### JavaScript (Fetch API) Examples

```javascript
// Base URL
const BASE_URL = 'http://localhost:8000/api/v1';

// Get dashboard overview
fetch(`${BASE_URL}/dashboard/overview`, {
  credentials: 'include' // Include cookies
})
  .then(response => response.json())
  .then(data => {
    console.log('Total packets:', data.total_packets);
  });

// Start packet capture
fetch(`${BASE_URL}/traffic/capture/start`, {
  method: 'POST',
  credentials: 'include'
})
  .then(response => response.json())
  .then(data => console.log(data));

// Analyze a packet
fetch(`${BASE_URL}/threats/analyze`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  credentials: 'include',
  body: JSON.stringify({
    source: '192.168.1.100',
    destination: '8.8.8.8',
    protocol: 'TCP',
    size: 1024,
    dst_port: 443
  })
})
  .then(response => response.json())
  .then(data => console.log('Analysis result:', data));
```

## Versioning

Current API version: `v1`

The API version is included in the URL path (`/api/v1/`). Future versions will use `/api/v2/`, etc.

## Support

For issues or questions:
- Check the main [DIDS documentation](../README.md)
- Review the [API source code](api/dashboard.py)
- Open an issue on GitHub

## Changelog

### Version 1.0.0 (2025-11-20)
- Initial API release
- Dashboard overview endpoint
- Traffic management endpoints
- Threat detection endpoints
- AI/ML endpoints
- System health endpoints
- Configuration endpoints
- Reports and analytics
- Alerts endpoints
- User management endpoints
