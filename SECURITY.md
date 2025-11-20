# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in DIDS, please report it to:

**Email**: security@dids-project.org (or create a private security advisory on GitHub)

**Please do NOT**:
- Create public GitHub issues for security vulnerabilities
- Discuss vulnerabilities in public forums or social media
- Attempt to exploit vulnerabilities in production systems

### What to Include in Your Report

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)
- Your contact information

We aim to respond to security reports within **48 hours** and provide a fix within **7-14 days** for critical vulnerabilities.

## Security Considerations

###1. Authentication & Authorization

#### Dashboard Authentication
- **Method**: Session-based authentication with Flask-Login
- **Password Hashing**: Bcrypt (cost factor: 12)
- **Session Management**:
  - HTTPOnly cookies (prevents XSS)
  - Secure flag enabled in production (HTTPS only)
  - Session timeout: 30 minutes of inactivity
  - CSRF protection enabled

```python
# Strong password requirements
Minimum length: 12 characters
Must include:
  - Uppercase letters (A-Z)
  - Lowercase letters (a-z)
  - Numbers (0-9)
  - Special characters (!@#$%^&*)
```

#### Role-Based Access Control (RBAC)

| Role | Permissions |
|------|-------------|
| **Admin** | Full system access, user management, system configuration, model deployment |
| **Analyst** | View/manage alerts, create reports, configure detection rules, limited user access |
| **Viewer** | Read-only access to dashboards and reports |
| **User** | Basic dashboard access, view own alerts |

**Implementation**:
```python
from utils.decorators import login_required, admin_required

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    # Only admins can access
    pass
```

### 2. Network Security

#### TLS/SSL Encryption

**Production Requirements**:
- All HTTP traffic MUST use HTTPS (TLS 1.2+)
- Strong cipher suites only
- Certificate validation enforced
- HSTS headers enabled

**Nginx Configuration** (recommended):
```nginx
server {
    listen 443 ssl http2;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    # Strong ciphers only
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

#### Microservice Communication

**Inter-service Authentication**:
- Service-to-service API keys
- JWT tokens for internal APIs
- Network policies in Kubernetes (zero trust)

**Network Isolation**:
```yaml
# Kubernetes Network Policy Example
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-api-gateway
spec:
  podSelector:
    matchLabels:
      app: ai-detection
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: api-gateway
```

#### Firewall Rules

- **Inbound**: Only ports 443 (HTTPS) and 22 (SSH with key-only auth)
- **Outbound**: Restricted to necessary services only
- **Internal**: Services only accessible within VPC/cluster

### 3. Data Protection

#### Sensitive Data Handling

**Personally Identifiable Information (PII)**:
- User passwords: NEVER stored in plaintext (Bcrypt hashed)
- Email addresses: Encrypted at rest
- IP addresses: Anonymized in logs (last octet masked)

**Network Traffic Data**:
- Packet payloads: NOT stored (only metadata)
- Flow records: Retained for 7 days, then purged
- Alert data: Anonymized before long-term storage

**Data at Rest Encryption**:
```yaml
# MongoDB with encryption
MongoDB:
  encryption:
    enabled: true
    keyVaultNamespace: admin.dataKeys
    provider: azure  # Azure Key Vault

# Kubernetes Secrets
kubectl create secret generic db-password \
  --from-literal=password=<strong-password> \
  --dry-run=client -o yaml | kubeseal -o yaml
```

**Data in Transit**:
- All API calls over HTTPS
- Redis connections use TLS
- MongoDB connections use TLS
- RabbitMQ uses TLS

#### Audit Logging

All security-relevant events are logged to the `system_logs` collection:

```python
Events logged:
- User login/logout (successful and failed)
- Permission changes
- Configuration changes
- Model deployments
- Alert acknowledgments
- Data exports
```

**Log Format**:
```json
{
  "timestamp": "2025-01-20T12:00:00Z",
  "event_type": "auth.login",
  "user_id": "user123",
  "ip_address": "192.168.1.x",  // Last octet masked
  "user_agent": "Mozilla/5.0...",
  "result": "success",
  "metadata": {}
}
```

**Log Retention**:
- System logs: 30 days (can be extended for compliance)
- Audit logs: 1 year minimum
- Security incident logs: Permanent

### 4. Input Validation & Sanitization

#### API Input Validation

**All user inputs are validated**:
```python
from utils.validators import validate_email, validate_ip, sanitize_input

# Example
@app.route('/api/threats/search', methods=['POST'])
@login_required
def search_threats():
    data = request.get_json()

    # Validate
    search_term = sanitize_input(data.get('query', ''))
    ip_address = validate_ip(data.get('ip'))

    if not search_term:
        return jsonify({'error': 'Invalid input'}), 400

    # Prevent SQL/NoSQL injection
    results = db.threats.find({'$text': {'$search': search_term}})
    return jsonify(results)
```

#### Protection Against Common Attacks

**SQL/NoSQL Injection**:
```python
# BAD - Vulnerable to injection
query = f"SELECT * FROM users WHERE email = '{user_input}'"

# GOOD - Parameterized queries
query = db.users.find_one({'email': user_input})
```

**Cross-Site Scripting (XSS)**:
```python
# All output escaped in templates
from flask import escape
output = escape(user_input)

# CSP headers
@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = \
        "default-src 'self'; script-src 'self' 'unsafe-inline'"
    return response
```

**Cross-Site Request Forgery (CSRF)**:
```python
# Flask-WTF CSRF protection enabled
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
```

**Command Injection**:
```python
# NEVER use shell=True
# BAD
os.system(f"ping {user_ip}")

# GOOD
subprocess.run(['ping', '-c', '1', validated_ip], shell=False)
```

### 5. Model Security

#### Model Integrity

**Model Versioning & Signing**:
- All models versioned in git
- Models cryptographically signed before deployment
- Checksum verification on load

```python
import hashlib

def verify_model(model_path, expected_hash):
    with open(model_path, 'rb') as f:
        model_hash = hashlib.sha256(f.read()).hexdigest()
    return model_hash == expected_hash
```

#### Adversarial Attack Protection

**RL Agent Safety Mechanisms**:
1. **Fail-safe Mode**: If confidence < threshold, default to ALERT (not ALLOW or BLOCK)
2. **Action Constraints**: Prevent dangerous action sequences
3. **Human Override**: Analysts can override RL decisions
4. **Rollback Capability**: Revert to previous model version

```python
# Fail-safe implementation
def get_action(state, confidence_threshold=0.85):
    action, confidence = rl_agent.predict(state)

    if confidence < confidence_threshold:
        # Low confidence - fail-safe to alert
        return Action.ALERT, "Low confidence"

    return action, "High confidence"
```

**Model Poisoning Prevention**:
- Training data sanitized and validated
- Only use trusted datasets (CICIDS, NSL-KDD)
- Monitor model performance for drift
- Regular model retraining with clean data

### 6. Secrets Management

#### Environment Variables

**NEVER commit secrets to git**:
```bash
# Use .env files (git-ignored)
.env
.env.local
.env.production

# Example .env
MONGODB_PASSWORD=<use-strong-password>
SECRET_KEY=<generate-with-secrets.token_urlsafe(32)>
```

#### Azure Key Vault Integration

```python
from azure.keyvault.secrets import SecretClient

# Fetch secrets from Key Vault
def get_secret(secret_name):
    client = SecretClient(
        vault_url=os.getenv('KEY_VAULT_URL'),
        credential=DefaultAzureCredential()
    )
    return client.get_secret(secret_name).value

# Usage
db_password = get_secret('mongodb-password')
```

#### Kubernetes Secrets

```yaml
# Create sealed secret
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: mongodb-secret
spec:
  encryptedData:
    password: AgBpEj7+... # Encrypted
```

### 7. Dependency Security

#### Regular Security Audits

```bash
# Python dependencies
pip-audit
safety check

# Docker images
trivy image dids-dashboard:latest

# Kubernetes manifests
kubesec scan k8s/deployment.yaml
```

#### Automated Vulnerability Scanning

**GitHub Dependabot**:
- Enabled for automatic PR creation
- Weekly security updates
- Auto-merge low-risk updates

**Container Scanning**:
```yaml
# .github/workflows/security.yml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: 'dids-dashboard:latest'
    severity: 'CRITICAL,HIGH'
```

### 8. Incident Response

#### Security Incident Playbook

**Detection**:
1. Automated alerts (failed login attempts, unusual traffic)
2. Security monitoring dashboard
3. Log analysis (ELK stack)

**Response**:
1. **Contain**: Isolate affected systems
2. **Investigate**: Analyze logs, identify root cause
3. **Eradicate**: Remove threat, patch vulnerabilities
4. **Recover**: Restore from clean backups
5. **Learn**: Post-incident review, update policies

**Contacts**:
- Security Lead: security@dids-project.org
- On-call Engineer: +1-XXX-XXX-XXXX
- Azure Support: Portal ticket

### 9. Compliance & Regulations

#### Data Protection Compliance

**GDPR** (if handling EU data):
- Right to be forgotten: User deletion mechanism
- Data portability: Export user data
- Consent management: Clear privacy policy
- Data breach notification: Within 72 hours

**Industry Standards**:
- **NIST Cybersecurity Framework**: Identify, Protect, Detect, Respond, Recover
- **OWASP Top 10**: Addressed in development
- **ISO 27001**: Information security management (optional certification)

### 10. Secure Development Practices

#### Code Review Process

- All code changes require review
- Security checklist for reviewers
- Automated security scanning (SonarQube, Semgrep)

#### Security Testing

```bash
# Static analysis
bandit -r dids-dashboard/
flake8 --select=S  # Security-related checks

# Dynamic analysis
OWASP ZAP automated scan

# Penetration testing
Schedule quarterly pen tests
```

## Security Checklist for Deployment

Before deploying to production, ensure:

- [ ] All services use HTTPS/TLS
- [ ] Strong passwords enforced
- [ ] RBAC configured correctly
- [ ] Secrets stored in Key Vault (not .env)
- [ ] Firewall rules configured
- [ ] Network policies applied (Kubernetes)
- [ ] Audit logging enabled
- [ ] Backup & disaster recovery tested
- [ ] Dependencies up-to-date (no critical vulnerabilities)
- [ ] Security monitoring enabled (Prometheus alerts)
- [ ] Incident response plan documented
- [ ] Privacy policy published
- [ ] Security training completed (team)

## Security Updates

This security policy is reviewed and updated:
- **Quarterly**: Regular security audit
- **After incidents**: Post-incident updates
- **When new threats emerge**: Ad-hoc updates

**Last Review**: 2025-01-20
**Next Review**: 2025-04-20

## Contact

For security questions or concerns:
- **Email**: security@dids-project.org
- **GitHub**: Create a private security advisory
- **Emergency**: +1-XXX-XXX-XXXX (on-call engineer)

---

**Remember**: Security is everyone's responsibility. If you see something, say something.
