# RL Agent Safety Mechanisms and Fallback Strategies

## Overview

This document outlines the comprehensive safety mechanisms, guardrails, and fallback strategies implemented in the DIDS Reinforcement Learning (RL) agent. Safety is critical in autonomous decision-making systems, especially in cybersecurity contexts where incorrect decisions can have serious consequences.

## Table of Contents

1. [Safety Philosophy](#safety-philosophy)
2. [Risk Analysis](#risk-analysis)
3. [Safety Mechanisms](#safety-mechanisms)
4. [Fail-Safe Modes](#fail-safe-modes)
5. [Confidence Thresholds](#confidence-thresholds)
6. [Action Constraints](#action-constraints)
7. [Human-in-the-Loop](#human-in-the-loop)
8. [Rollback Procedures](#rollback-procedures)
9. [Monitoring and Alerts](#monitoring-and-alerts)
10. [Testing and Validation](#testing-and-validation)

## Safety Philosophy

### Core Principles

1. **Safety First**: When in doubt, choose the safer action (ALERT over ALLOW or QUARANTINE)
2. **Human Oversight**: Critical decisions require human confirmation
3. **Gradual Autonomy**: Start conservative, increase autonomy with proven performance
4. **Reversibility**: All actions must be reversible or overridable
5. **Transparency**: All decisions must be explainable and auditable
6. **Defensive Design**: Assume the agent will make mistakes and plan accordingly

### Safety Levels

```
Level 0: Advisory Mode (Human decides everything)
    └─> RL agent provides recommendations only
    └─> No automatic actions

Level 1: Assisted Mode (Human confirms high-risk actions)
    └─> Auto-allow benign traffic
    └─> Human confirms quarantine decisions
    └─> Default mode for production

Level 2: Semi-Autonomous (Human monitors)
    └─> Agent makes all decisions
    └─> Human can override within 30 seconds
    └─> Requires proven track record

Level 3: Fully Autonomous (Human supervises)
    └─> Agent operates independently
    └─> Only for mature deployments
    └─> Requires months of Level 2 operation
```

**Default**: Level 1 (Assisted Mode)

## Risk Analysis

### Potential Failure Modes

| Failure Mode | Impact | Likelihood | Mitigation |
|--------------|--------|------------|------------|
| **False Positive** (Block benign traffic) | High | Medium | Confidence thresholds, human review |
| **False Negative** (Allow attack) | Critical | Low | Multi-layer detection, fail-safe |
| **Model Drift** (Performance degrades) | High | Medium | Continuous monitoring, auto-rollback |
| **Adversarial Attack** (Evasion) | Critical | Low | Ensemble detection, anomaly checks |
| **Resource Exhaustion** (DoS on agent) | Medium | Low | Rate limiting, timeout protection |
| **Training Poisoning** (Bad data) | High | Low | Data validation, trusted datasets |

### Risk Matrix

```
Impact vs Likelihood

Critical  │     [FN]              [Adv]
          │
High      │  [FP]  [Drift]     [Poison]
          │
Medium    │              [DoS]
          │
Low       │
          └────────────────────────────────
           Low    Medium    High   Critical
                  Likelihood

Legend:
FN = False Negative
FP = False Positive
Drift = Model Drift
Adv = Adversarial Attack
DoS = Resource Exhaustion
Poison = Training Poisoning
```

## Safety Mechanisms

### 1. Confidence-Based Decision Making

```python
# rl_module/agents/dqn_agent.py

def act_with_confidence(self, state, confidence_threshold=0.85):
    """
    Make decision with confidence check

    Returns:
        action: int (0=ALLOW, 1=ALERT, 2=QUARANTINE)
        confidence: float (0-1)
        reason: str (explanation)
    """
    # Get Q-values for all actions
    q_values = self.model.predict(state, verbose=0)[0]

    # Best action
    best_action = np.argmax(q_values)
    best_q = q_values[best_action]

    # Second best action
    second_q = np.partition(q_values, -2)[-2]

    # Calculate confidence (margin between best and second-best)
    confidence = (best_q - second_q) / (best_q + 1e-8)

    # SAFETY CHECK: Low confidence triggers fail-safe
    if confidence < confidence_threshold:
        return (
            Action.ALERT,  # Fail-safe action
            confidence,
            f"Low confidence ({confidence:.2f}), using fail-safe"
        )

    return best_action, confidence, "High confidence"
```

**Rationale**: When the agent is uncertain, default to ALERT (human review) rather than ALLOW (potential attack) or QUARANTINE (potential false positive).

### 2. Multi-Layer Validation

```python
# rl_module/agents/safety_validator.py

class SafetyValidator:
    """Validate RL decisions before execution"""

    def validate_action(self, state, action, confidence):
        """
        Multi-layer validation of RL decision

        Returns:
            is_safe: bool
            final_action: int (possibly modified)
            reason: str
        """
        checks = [
            self._check_confidence(action, confidence),
            self._check_state_validity(state),
            self._check_action_consistency(state, action),
            self._check_rate_limits(action),
            self._check_business_rules(state, action)
        ]

        for check in checks:
            if not check['passed']:
                return False, Action.ALERT, check['reason']

        return True, action, "All safety checks passed"

    def _check_confidence(self, action, confidence):
        """Ensure confidence is above threshold for risky actions"""
        if action == Action.QUARANTINE and confidence < 0.90:
            return {
                'passed': False,
                'reason': 'Insufficient confidence for QUARANTINE'
            }
        return {'passed': True}

    def _check_state_validity(self, state):
        """Ensure state features are within valid ranges"""
        if np.any(np.isnan(state)) or np.any(np.isinf(state)):
            return {
                'passed': False,
                'reason': 'Invalid state (NaN or Inf detected)'
            }
        return {'passed': True}

    def _check_action_consistency(self, state, action):
        """Check if action is consistent with anomaly detection"""
        anomaly_score = state[0]  # First feature is anomaly score

        # If anomaly detection says BENIGN, don't QUARANTINE
        if anomaly_score < 0.3 and action == Action.QUARANTINE:
            return {
                'passed': False,
                'reason': 'Action conflicts with anomaly detection'
            }

        return {'passed': True}

    def _check_rate_limits(self, action):
        """Prevent excessive quarantine actions"""
        recent_quarantines = self._get_recent_actions(Action.QUARANTINE, minutes=5)

        if len(recent_quarantines) > 100:  # Max 100 quarantines per 5 min
            return {
                'passed': False,
                'reason': 'Rate limit exceeded (possible DoS on agent)'
            }

        return {'passed': True}

    def _check_business_rules(self, state, action):
        """Apply business-specific rules"""
        src_ip = self._extract_ip(state)

        # Never block whitelisted IPs
        if src_ip in WHITELIST and action == Action.QUARANTINE:
            return {
                'passed': False,
                'reason': f'IP {src_ip} is whitelisted'
            }

        # Always alert on IPs from certain countries (compliance)
        if self._is_restricted_country(src_ip) and action == Action.ALLOW:
            return {
                'passed': False,
                'reason': 'Traffic from restricted country must be reviewed'
            }

        return {'passed': True}
```

### 3. Ensemble Decision Making

```python
# rl_module/agents/ensemble_agent.py

class EnsembleAgent:
    """Combine multiple agents for robust decisions"""

    def __init__(self):
        self.agents = [
            load_agent('double_dqn_final.keras'),    # Primary
            load_agent('double_dqn_backup.keras'),   # Backup
            load_agent('dqn_conservative.keras')     # Conservative baseline
        ]
        self.weights = [0.6, 0.3, 0.1]  # Weighted voting

    def decide(self, state):
        """Ensemble decision with voting"""
        votes = []
        confidences = []

        for agent, weight in zip(self.agents, self.weights):
            action, confidence = agent.act_with_confidence(state)
            votes.append((action, weight, confidence))
            confidences.append(confidence)

        # Weighted voting
        action_scores = {0: 0, 1: 0, 2: 0}
        for action, weight, confidence in votes:
            action_scores[action] += weight * confidence

        final_action = max(action_scores, key=action_scores.get)
        avg_confidence = np.mean(confidences)

        # SAFETY: If agents disagree significantly, fail-safe to ALERT
        if self._high_disagreement(votes):
            return Action.ALERT, 0.5, "High disagreement among agents"

        return final_action, avg_confidence, "Ensemble consensus"

    def _high_disagreement(self, votes):
        """Check if agents strongly disagree"""
        actions = [v[0] for v in votes]
        # If all three agents chose different actions
        return len(set(actions)) == 3
```

## Fail-Safe Modes

### 1. Confidence-Based Fail-Safe

```python
# Default behavior for low confidence
if confidence < CONFIDENCE_THRESHOLD:
    action = Action.ALERT  # Request human review
    log.warning(f"Low confidence ({confidence:.2f}), using fail-safe")
```

**Thresholds**:
- `ALLOW`: No minimum confidence (lowest risk)
- `ALERT`: No minimum (fail-safe action)
- `QUARANTINE`: 0.85 minimum (high risk, needs confidence)

### 2. Resource Exhaustion Fail-Safe

```python
# rl_module/agents/resource_monitor.py

class ResourceMonitor:
    """Monitor and protect against resource exhaustion"""

    def check_resources(self):
        """Check if system resources are healthy"""
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_usage = psutil.virtual_memory().percent
        queue_depth = self._get_queue_depth()

        if cpu_usage > 90:
            return {
                'safe': False,
                'mode': 'DEGRADED',
                'reason': 'High CPU usage'
            }

        if memory_usage > 85:
            return {
                'safe': False,
                'mode': 'DEGRADED',
                'reason': 'High memory usage'
            }

        if queue_depth > 1000:
            return {
                'safe': False,
                'mode': 'DEGRADED',
                'reason': 'Queue backlog'
            }

        return {'safe': True, 'mode': 'NORMAL'}

# In degraded mode:
# - Skip RL inference (too slow)
# - Use simple rule-based decisions
# - Alert operators
```

### 3. Model Failure Fail-Safe

```python
# Handle model inference errors gracefully
try:
    action, confidence = agent.act_with_confidence(state)
except Exception as e:
    log.error(f"RL agent error: {e}")
    # FAIL-SAFE: Use anomaly detection only
    if anomaly_score > 0.7:
        action = Action.ALERT
    else:
        action = Action.ALLOW

    # Alert operators about model failure
    send_alert("RL agent failed, using fallback logic")
```

### 4. Fallback to Rule-Based System

```python
# rl_module/fallback/rule_based.py

class RuleBasedFallback:
    """Simple rule-based system as last resort"""

    def decide(self, features):
        """Traditional rule-based decision"""

        # DDoS indicators
        if features['packet_rate'] > 10000 and features['syn_ratio'] > 0.8:
            return Action.QUARANTINE, "High packet rate + SYN flood"

        # Port scan indicators
        if features['unique_ports'] > 100 and features['time_window'] < 10:
            return Action.QUARANTINE, "Port scan detected"

        # Brute force indicators
        if features['failed_logins'] > 10 and features['time_window'] < 60:
            return Action.QUARANTINE, "Brute force detected"

        # Default: Allow
        return Action.ALLOW, "No obvious threats"

# Used when RL agent is unavailable
if RL_AGENT_AVAILABLE:
    action = rl_agent.decide(state)
else:
    action = rule_based_fallback.decide(features)
```

## Confidence Thresholds

### Dynamic Threshold Adjustment

```python
# rl_module/agents/adaptive_threshold.py

class AdaptiveThreshold:
    """Dynamically adjust confidence thresholds based on performance"""

    def __init__(self):
        self.base_threshold = 0.85
        self.adjustment_window = 1000  # Last 1000 decisions
        self.target_fpr = 0.02  # Target 2% false positive rate

    def get_threshold(self):
        """Calculate current threshold"""
        recent_decisions = self._get_recent_decisions(self.adjustment_window)
        current_fpr = self._calculate_fpr(recent_decisions)

        # If FPR too high, increase threshold (more conservative)
        if current_fpr > self.target_fpr * 1.2:
            adjustment = +0.05
        # If FPR too low, decrease threshold (less conservative)
        elif current_fpr < self.target_fpr * 0.8:
            adjustment = -0.02
        else:
            adjustment = 0

        new_threshold = np.clip(
            self.base_threshold + adjustment,
            min=0.70,  # Never go below 0.70
            max=0.95   # Never go above 0.95
        )

        log.info(f"Threshold adjusted to {new_threshold:.2f} (FPR: {current_fpr:.3f})")
        return new_threshold
```

### Per-Action Thresholds

```yaml
# config/rl_safety.yaml

confidence_thresholds:
  ALLOW:
    minimum: 0.50  # Low risk, allow with moderate confidence
    recommended: 0.70

  ALERT:
    minimum: 0.00  # No minimum (fail-safe action)
    recommended: 0.50

  QUARANTINE:
    minimum: 0.85  # High risk, require high confidence
    recommended: 0.90
    critical_assets: 0.95  # Even higher for critical systems
```

## Action Constraints

### 1. Temporal Constraints

```python
# Prevent rapid action changes
class ActionConstraints:
    def __init__(self):
        self.last_action = {}  # {ip: (action, timestamp)}
        self.min_action_duration = 60  # seconds

    def can_change_action(self, ip, new_action):
        """Prevent too-frequent action changes"""
        if ip not in self.last_action:
            return True

        last_action, timestamp = self.last_action[ip]
        time_elapsed = time.time() - timestamp

        # Must wait at least min_action_duration before changing
        if time_elapsed < self.min_action_duration:
            log.warning(
                f"Action change too soon for {ip} "
                f"({time_elapsed:.0f}s < {self.min_action_duration}s)"
            )
            return False

        return True
```

### 2. Spatial Constraints

```python
# Prevent quarantining entire networks
class NetworkConstraints:
    def __init__(self):
        self.max_quarantine_per_subnet = 0.3  # Max 30% of subnet

    def can_quarantine(self, ip):
        """Check if we can quarantine this IP"""
        subnet = self._get_subnet(ip)
        total_ips = self._get_subnet_size(subnet)
        quarantined_ips = self._get_quarantined_count(subnet)

        ratio = quarantined_ips / total_ips

        if ratio > self.max_quarantine_per_subnet:
            log.warning(
                f"Cannot quarantine {ip}: "
                f"subnet {subnet} already has {ratio:.1%} quarantined"
            )
            return False

        return True
```

### 3. Business Logic Constraints

```python
# Never block critical infrastructure
WHITELIST = [
    '192.168.1.1',      # Gateway
    '192.168.1.10',     # DNS server
    '192.168.1.100',    # Domain controller
    '10.0.0.0/8',       # Internal network
]

BLACKLIST = [
    '0.0.0.0/8',        # Invalid
    '127.0.0.0/8',      # Loopback
    '169.254.0.0/16',   # Link-local
]

def is_whitelisted(ip):
    return ip in WHITELIST

def is_blacklisted(ip):
    return ip in BLACKLIST

# In decision logic:
if is_whitelisted(src_ip) and action == Action.QUARANTINE:
    action = Action.ALERT  # Override to ALERT instead
    reason = "Whitelisted IP, manual review required"
```

## Human-in-the-Loop

### 1. Approval Workflow

```python
# rl_module/human_loop/approval.py

class ApprovalWorkflow:
    """Require human approval for certain actions"""

    def requires_approval(self, action, confidence, impact):
        """Determine if action requires human approval"""

        # Always approve low-risk actions
        if action == Action.ALLOW:
            return False

        # ALERT never needs approval (it IS the human review)
        if action == Action.ALERT:
            return False

        # QUARANTINE requires approval if:
        rules = [
            confidence < 0.90,              # Low confidence
            impact == 'HIGH',               # High business impact
            self._is_critical_asset(),     # Critical infrastructure
            self._is_business_hours()      # During business hours (humans available)
        ]

        return any(rules)

    def request_approval(self, action, state, confidence, reason):
        """Send approval request to human operator"""
        request = {
            'timestamp': time.time(),
            'action': action,
            'confidence': confidence,
            'reason': reason,
            'state_summary': self._summarize_state(state),
            'timeout': 30  # seconds
        }

        # Send to dashboard for human review
        redis_client.publish('approval_requests', json.dumps(request))

        # Wait for response (with timeout)
        response = self._wait_for_approval(request['id'], timeout=30)

        if response is None:
            # Timeout: Use fail-safe
            log.warning("Approval timeout, using fail-safe")
            return Action.ALERT

        return response['approved_action']
```

### 2. Override Mechanism

```python
# Dashboard API endpoint
@app.route('/api/rl/override', methods=['POST'])
@login_required
@analyst_required
def override_rl_decision():
    """Allow human analyst to override RL decision"""
    data = request.get_json()

    alert_id = data['alert_id']
    override_action = data['action']
    reason = data['reason']

    # Log override for audit
    log_override(
        user=current_user,
        alert_id=alert_id,
        original_action=data['original_action'],
        override_action=override_action,
        reason=reason
    )

    # Apply override
    apply_action(alert_id, override_action)

    # Use override for future learning
    store_for_retraining(
        state=data['state'],
        correct_action=override_action
    )

    return jsonify({'success': True})
```

### 3. Feedback Loop

```python
# Learn from human corrections
class HumanFeedbackLearning:
    """Incorporate human feedback into RL training"""

    def __init__(self):
        self.feedback_buffer = []

    def add_feedback(self, state, rl_action, human_action, reason):
        """Record human correction"""
        self.feedback_buffer.append({
            'state': state,
            'rl_action': rl_action,
            'human_action': human_action,
            'reason': reason,
            'timestamp': time.time()
        })

    def retrain_with_feedback(self, agent):
        """Periodically retrain with human feedback"""
        if len(self.feedback_buffer) < 100:
            return  # Need enough samples

        # Create training samples from feedback
        for feedback in self.feedback_buffer:
            state = feedback['state']
            correct_action = feedback['human_action']

            # High reward for correct action (human-verified)
            reward = 100

            # Add to replay buffer
            agent.remember(state, correct_action, reward, state, True)

        # Retrain
        agent.replay(batch_size=32)

        # Clear buffer
        self.feedback_buffer = []

        log.info("Agent retrained with human feedback")
```

## Rollback Procedures

### 1. Model Versioning

```python
# rl_module/versioning/model_manager.py

class ModelManager:
    """Manage RL model versions with rollback capability"""

    def __init__(self):
        self.current_version = 'v1.2.0'
        self.models = {
            'v1.2.0': '/models/double_dqn_v1.2.0.keras',
            'v1.1.0': '/models/double_dqn_v1.1.0.keras',
            'v1.0.0': '/models/double_dqn_v1.0.0.keras',
        }
        self.performance_history = {}

    def deploy_model(self, version):
        """Deploy a specific model version"""
        if version not in self.models:
            raise ValueError(f"Model version {version} not found")

        # Load new model
        new_model = load_model(self.models[version])

        # Test new model on validation set
        performance = self._validate_model(new_model)

        # Only deploy if performance is acceptable
        if performance['accuracy'] < 0.95:
            log.error(f"Model {version} failed validation")
            return False

        # Backup current model
        self._backup_current_model()

        # Deploy new model
        self.current_model = new_model
        self.current_version = version

        log.info(f"Deployed model {version}")
        return True

    def rollback(self, to_version=None):
        """Rollback to previous model version"""
        if to_version is None:
            # Rollback to previous version
            versions = sorted(self.models.keys(), reverse=True)
            current_idx = versions.index(self.current_version)
            to_version = versions[current_idx + 1]

        log.warning(f"Rolling back from {self.current_version} to {to_version}")

        return self.deploy_model(to_version)

    def auto_rollback_check(self):
        """Automatically rollback if performance degrades"""
        recent_performance = self._get_recent_performance(hours=1)

        if recent_performance['accuracy'] < 0.90:
            log.critical(
                f"Performance degradation detected "
                f"(accuracy: {recent_performance['accuracy']:.2%})"
            )
            self.rollback()
```

### 2. Canary Deployment

```python
# Gradually roll out new models
class CanaryDeployment:
    """Deploy new model to small percentage of traffic first"""

    def __init__(self):
        self.canary_percentage = 0.05  # 5% of traffic
        self.canary_model = None
        self.production_model = None

    def route_request(self, state):
        """Route request to canary or production model"""

        # Random selection based on percentage
        if random.random() < self.canary_percentage:
            # Use canary model
            action, confidence = self.canary_model.act(state)
            log.debug("Used canary model")
        else:
            # Use production model
            action, confidence = self.production_model.act(state)

        return action, confidence

    def promote_canary(self):
        """Promote canary to production if performing well"""
        canary_perf = self._get_canary_performance()
        production_perf = self._get_production_performance()

        # Promote if canary is better or equal
        if canary_perf['f1_score'] >= production_perf['f1_score']:
            log.info("Promoting canary to production")
            self.production_model = self.canary_model
            self.canary_model = None
            return True
        else:
            log.warning("Canary performance insufficient, not promoting")
            return False
```

## Monitoring and Alerts

### Key Safety Metrics

```python
# Prometheus metrics for safety monitoring
safety_metrics = {
    'rl_decisions_total': Counter('rl_decisions_total', 'Total RL decisions', ['action']),
    'rl_confidence': Histogram('rl_confidence', 'RL confidence scores'),
    'rl_failsafe_triggered': Counter('rl_failsafe_triggered', 'Fail-safe activations', ['reason']),
    'rl_human_overrides': Counter('rl_human_overrides', 'Human overrides', ['action']),
    'rl_false_positives': Counter('rl_false_positives', 'Confirmed false positives'),
    'rl_false_negatives': Counter('rl_false_negatives', 'Confirmed false negatives'),
    'rl_model_errors': Counter('rl_model_errors', 'Model inference errors'),
}
```

### Safety Alerts

```yaml
# Prometheus alert rules
groups:
  - name: rl_safety
    rules:
      - alert: RLHighFalsePositiveRate
        expr: rate(rl_false_positives[1h]) > 0.05
        for: 10m
        annotations:
          summary: "RL agent false positive rate too high"
          action: "Review recent decisions, consider rollback"

      - alert: RLLowConfidence
        expr: histogram_quantile(0.95, rl_confidence) < 0.70
        for: 15m
        annotations:
          summary: "RL agent confidence too low"
          action: "Check model health, consider retraining"

      - alert: RLFrequentFailsafe
        expr: rate(rl_failsafe_triggered[5m]) > 0.5
        for: 5m
        annotations:
          summary: "Fail-safe activating too frequently"
          action: "Investigate root cause, check data quality"

      - alert: RLModelErrors
        expr: rate(rl_model_errors[5m]) > 0.01
        for: 5m
        annotations:
          summary: "RL model inference errors"
          action: "Check model health, consider rollback"

      - alert: RLFrequentOverrides
        expr: rate(rl_human_overrides[1h]) > 0.10
        for: 30m
        annotations:
          summary: "Humans overriding RL decisions frequently"
          action: "Retrain model with recent corrections"
```

## Testing and Validation

### Safety Testing

```python
# tests/safety/test_rl_safety.py

def test_fail_safe_on_low_confidence():
    """Test fail-safe activates when confidence is low"""
    agent = DoubleDQNAgent()

    # Create ambiguous state
    state = create_ambiguous_state()

    action, confidence = agent.act_with_confidence(state)

    if confidence < 0.85:
        assert action == Action.ALERT, "Fail-safe should trigger on low confidence"

def test_whitelist_protection():
    """Test whitelisted IPs cannot be quarantined"""
    agent = DoubleDQNAgent()
    validator = SafetyValidator()

    # Create state for whitelisted IP
    state = create_state(src_ip='192.168.1.1')  # Gateway (whitelisted)

    action = agent.act(state)

    # Even if agent says QUARANTINE, validator should block it
    is_safe, final_action, reason = validator.validate_action(state, Action.QUARANTINE, 0.99)

    assert not is_safe
    assert final_action == Action.ALERT
    assert 'whitelisted' in reason.lower()

def test_rate_limit_protection():
    """Test rate limiting prevents DoS on quarantine"""
    agent = DoubleDQNAgent()
    validator = SafetyValidator()

    # Simulate 150 quarantine actions in 5 minutes
    for _ in range(150):
        validator._log_action(Action.QUARANTINE)

    # Next quarantine should be blocked
    is_safe, final_action, reason = validator.validate_action(
        state=random_state(),
        action=Action.QUARANTINE,
        confidence=0.95
    )

    assert not is_safe
    assert 'rate limit' in reason.lower()

def test_rollback_on_performance_degradation():
    """Test automatic rollback when performance drops"""
    manager = ModelManager()

    # Simulate performance drop
    simulate_poor_performance(accuracy=0.85)

    # Check should trigger rollback
    manager.auto_rollback_check()

    # Verify rollback occurred
    assert manager.current_version != 'v1.2.0'
```

## Configuration

### Safety Configuration File

```yaml
# config/rl_safety.yaml

safety:
  # Operating mode
  mode: assisted  # advisory | assisted | semi_autonomous | autonomous

  # Confidence thresholds
  confidence:
    allow: 0.50
    alert: 0.00
    quarantine: 0.85
    adaptive: true

  # Fail-safe settings
  fail_safe:
    enabled: true
    low_confidence_threshold: 0.85
    fallback_action: alert

  # Rate limiting
  rate_limits:
    max_quarantines_per_5min: 100
    max_alerts_per_minute: 50

  # Constraints
  constraints:
    min_action_duration_seconds: 60
    max_subnet_quarantine_ratio: 0.30

  # Human oversight
  human_oversight:
    require_approval_for_quarantine: true
    approval_timeout_seconds: 30
    business_hours_only: true

  # Monitoring
  monitoring:
    performance_check_interval_minutes: 5
    auto_rollback_threshold: 0.90
    alert_on_frequent_failsafe: true

  # Whitelists/Blacklists
  whitelist:
    - 192.168.1.1      # Gateway
    - 192.168.1.10     # DNS
    - 10.0.0.0/8       # Internal

  blacklist:
    - 0.0.0.0/8
    - 127.0.0.0/8
```

## Best Practices

1. **Start Conservative**: Begin with Advisory or Assisted mode, gradually increase autonomy
2. **Monitor Continuously**: Watch safety metrics, set up alerts
3. **Human Feedback**: Regularly review and correct agent decisions
4. **Test Thoroughly**: Run safety tests before deploying new models
5. **Document Decisions**: Log all decisions with explanations for audit
6. **Rollback Quickly**: Don't hesitate to rollback if issues arise
7. **Regular Audits**: Review safety mechanisms quarterly
8. **Update Whitelists**: Keep critical asset lists up-to-date
9. **Train Operators**: Ensure humans understand how to override agent
10. **Learn from Incidents**: Use every safety incident to improve mechanisms

## Conclusion

Safety is paramount in autonomous cybersecurity systems. DIDS implements multiple layers of safety mechanisms to ensure:

✅ **Fail-Safe Behavior**: Defaults to safe actions when uncertain
✅ **Human Oversight**: Critical decisions require human approval
✅ **Reversibility**: All actions can be overridden or rolled back
✅ **Transparency**: All decisions are explainable and auditable
✅ **Robustness**: Multiple validation layers prevent catastrophic failures

**Remember**: The goal is not perfect autonomy, but safe and effective automation that augments human decision-making.

---

**Last Updated**: 2025-01-20
**Next Review**: 2025-04-20
**Maintained By**: DIDS Security Team
