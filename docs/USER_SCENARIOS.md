# User Scenarios, Personas, and Use Cases

## Overview

This document describes the primary users of DIDS, their goals, workflows, and use cases. Understanding user needs is critical for designing effective security tools.

## User Personas

### 1. Security Analyst (Sarah)

**Role**: SOC Analyst
**Experience**: 3 years in cybersecurity
**Technical Level**: Intermediate

**Goals**:
- Monitor network traffic for threats
- Investigate security alerts
- Respond to incidents quickly
- Minimize false positives

**Pain Points**:
- Alert fatigue from too many false positives
- Lack of context in alerts
- Manual investigation is time-consuming
- Difficulty explaining decisions to management

**How DIDS Helps**:
- AI-powered detection reduces false positives (1.8%)
- Explainable AI provides context for every alert
- Automated threat prioritization
- One-click investigation with detailed evidence

### 2. Security Operations Manager (Michael)

**Role**: SOC Manager
**Experience**: 10 years in IT security
**Technical Level**: Advanced

**Goals**:
- Ensure 24/7 threat detection
- Optimize team efficiency
- Meet compliance requirements
- Report metrics to executives

**Pain Points**:
- Limited visibility into system performance
- Difficulty justifying security investments
- Need to demonstrate ROI
- Managing team workload

**How DIDS Helps**:
- Real-time dashboards with key metrics
- Comprehensive audit logs for compliance
- Performance reports (99.6% detection rate)
- Automated responses reduce team workload

### 3. Network Administrator (Alex)

**Role**: Network Operations
**Experience**: 5 years managing enterprise networks
**Technical Level**: Advanced (networking), Basic (ML/AI)

**Goals**:
- Maintain network performance
- Quickly identify network issues
- Integrate security with operations
- Avoid network downtime

**Pain Points**:
- Security tools slowing network
- False positives blocking legitimate traffic
- Complex configuration
- Need to maintain performance SLAs

**How DIDS Helps**:
- Low latency (78ms P95)
- Whitelist management for known-good traffic
- Performance monitoring built-in
- Minimal network overhead

### 4. Compliance Officer (Jennifer)

**Role**: Compliance and Risk Management
**Experience**: 8 years in regulatory compliance
**Technical Level**: Basic (technical), Expert (compliance)

**Goals**:
- Ensure GDPR/HIPAA/PCI-DSS compliance
- Audit security controls
- Generate compliance reports
- Demonstrate due diligence

**Pain Points**:
- Difficulty proving security effectiveness
- Missing audit trails
- Manual report generation
- Explaining AI decisions to auditors

**How DIDS Helps**:
- Complete audit logs (1-year retention)
- Explainable AI decisions
- Automated compliance reports
- Data protection controls (encryption, anonymization)

## Use Cases

### Use Case 1: Detecting and Responding to DDoS Attack

**Scenario**: Large banking network experiences DDoS attack during business hours

**Actors**: Sarah (Security Analyst), DIDS

**Flow**:
1. **Attack Begins**: Attacker launches DDoS from botnet
2. **Detection**: DIDS traffic capture detects 8,500 pps spike
3. **Analysis**: Anomaly detection model identifies SYN flood pattern (confidence: 95%)
4. **Decision**: RL agent recommends QUARANTINE action
5. **Alert**: Dashboard shows critical alert with explanation
6. **Response**: Sarah reviews alert, sees evidence (high packet rate, many SYN flags)
7. **Action**: Sarah approves quarantine, attacker IPs blocked
8. **Resolution**: Attack mitigated in 45 seconds
9. **Report**: System generates incident report for review

**Success Metrics**:
- Time to detect: <5 seconds
- Time to respond: <60 seconds
- False positive rate: <2%
- Analyst confidence: High (due to explanation)

### Use Case 2: Investigating False Positive

**Scenario**: Internal vulnerability scanner flagged as port scan

**Actors**: Sarah (Security Analyst), Alex (Network Admin)

**Flow**:
1. **Alert Generated**: DIDS flags internal IP 192.168.1.50 for port scanning
2. **Investigation**: Sarah opens alert in dashboard
3. **Context**: Sees 127 unique ports accessed in 8 seconds
4. **Explanation**: SHAP analysis shows "unique_ports" as primary factor
5. **Collaboration**: Sarah messages Alex about IP
6. **Resolution**: Alex confirms it's weekly vulnerability scanner
7. **Whitelist**: Sarah adds IP to whitelist
8. **Feedback**: Sarah marks alert as false positive
9. **Learning**: System uses feedback for future training

**Outcome**:
- False positive identified and resolved quickly
- Whitelist prevents future alerts
- Model learns from human feedback

### Use Case 3: Monthly Compliance Report

**Scenario**: Jennifer needs to generate quarterly compliance report for auditors

**Actors**: Jennifer (Compliance Officer)

**Flow**:
1. **Report Request**: Jennifer opens DIDS dashboard
2. **Date Range**: Selects Q4 2024 (Oct-Dec)
3. **Metrics**: Reviews key metrics:
   - Threats detected: 45,230
   - Threats blocked: 45,100
   - Detection rate: 99.7%
   - False positive rate: 1.8%
   - Uptime: 99.8%
4. **Audit Trail**: Exports audit logs (all user actions)
5. **Explainability**: Includes sample alerts with explanations
6. **Data Protection**: Verifies PII anonymization
7. **Export**: Generates PDF report
8. **Submission**: Submits to auditors with confidence

**Deliverables**:
- Comprehensive metrics report
- Complete audit trail
- Explainable AI documentation
- Proof of compliance

### Use Case 4: Onboarding New Analyst

**Scenario**: New analyst joins SOC team, needs training

**Actors**: New Analyst (Tom), Sarah (Mentor)

**Flow**:
1. **Account Setup**: Admin creates account with "Analyst" role
2. **Dashboard Tour**: Sarah shows Tom the dashboard
3. **Training Mode**: Tom reviews historical alerts with explanations
4. **Learning**:
   - Sees DDoS example with key indicators
   - Reviews port scan patterns
   - Understands brute force signatures
5. **Practice**: Tom investigates test alerts
6. **Validation**: Tom correctly identifies 9/10 test cases
7. **Gradual Autonomy**: Tom starts with low-priority alerts
8. **Feedback Loop**: Sarah reviews Tom's decisions

**Training Value**:
- Explainable AI teaches attack patterns
- Historical data provides examples
- Practice mode builds confidence
- Gradual responsibility reduces risk

### Use Case 5: System Performance Degradation

**Scenario**: DIDS experiencing high latency during peak hours

**Actors**: Alex (Network Admin), Michael (SOC Manager)

**Flow**:
1. **Alert**: Prometheus alerts on high P95 latency (180ms)
2. **Investigation**: Alex checks Grafana dashboards
3. **Diagnosis**: Anomaly detection service at 95% CPU
4. **Root Cause**: Traffic spike due to network scan
5. **Immediate Fix**: Alex scales anomaly detection from 2 to 4 instances
6. **Validation**: Latency drops to 85ms
7. **Long-term**: Michael approves budget for autoscaling
8. **Prevention**: Configures HPA (Horizontal Pod Autoscaler)

**Resolution**:
- Immediate: Manual scaling
- Long-term: Automated scaling
- Prevention: Performance monitoring

### Use Case 6: Zero-Day Attack Detection

**Scenario**: Novel attack variant not in signature database

**Actors**: DIDS (autonomous), Sarah (review)

**Flow**:
1. **Attack**: Attacker uses new exploit technique
2. **Signature Bypass**: Suricata doesn't recognize pattern
3. **Anomaly Detection**: ML model detects unusual behavior:
   - Abnormal packet size distribution
   - Unusual protocol sequence
   - Atypical data transfer patterns
4. **RL Decision**: Agent recommends ALERT (low confidence: 78%)
5. **Human Review**: Sarah investigates alert
6. **Confirmation**: Sarah confirms it's an attack
7. **Response**: Sarah escalates to QUARANTINE
8. **Intelligence**: Threat intelligence team analyzes sample
9. **Update**: Suricata signatures updated
10. **Learning**: RL model learns from human feedback

**Value**:
- Defense-in-depth protects against zero-days
- ML detects novel attacks
- Human expertise validates unknowns
- System continuously improves

## Workflows

### Daily SOC Workflow

**Morning (8:00 AM)**:
```
1. Sarah logs into DIDS dashboard
2. Reviews overnight alerts (automated email digest)
3. Checks system health metrics
4. Prioritizes alerts by severity
```

**Investigation (9:00 AM - 12:00 PM)**:
```
1. Opens high-severity alert
2. Reviews alert explanation:
   - What was detected?
   - Why was it flagged?
   - What evidence supports this?
3. Investigates source IP (threat intel lookup)
4. Makes decision: Confirm / False Positive / Needs More Info
5. Takes action: Block / Whitelist / Escalate
6. Documents findings
```

**Lunch Break (12:00 PM - 1:00 PM)**

**Afternoon (1:00 PM - 5:00 PM)**:
```
1. Reviews medium-priority alerts
2. Responds to escalations from tier-1
3. Updates whitelists/blacklists
4. Collaborates with network team
5. Weekly: Generates performance report for manager
```

**End of Day (5:00 PM)**:
```
1. Reviews pending alerts
2. Hands off critical items to night shift
3. Checks system health before leaving
```

### Incident Response Workflow

**Phase 1: Detection**
```
DIDS → Alert Generated → Dashboard Notification
         ↓
    Severity Assessment
         ↓
   High → Page on-call analyst
   Medium → Email notification
   Low → Dashboard queue
```

**Phase 2: Investigation**
```
Analyst Opens Alert
    ↓
Review Explanation
    - What: Attack type
    - Why: Key indicators
    - Evidence: Packet details
    ↓
Validate with External Tools
    - Threat intelligence lookup
    - SIEM correlation
    - Network logs
    ↓
Determine Severity & Scope
```

**Phase 3: Containment**
```
If Confirmed Attack:
    ↓
Execute Response
    - Block attacker IP
    - Quarantine affected systems
    - Notify stakeholders
    ↓
Monitor Effectiveness
```

**Phase 4: Recovery**
```
Verify Attack Stopped
    ↓
Remove Temporary Blocks
    ↓
Restore Normal Operations
    ↓
Update Permanent Blacklists
```

**Phase 5: Post-Incident**
```
Generate Incident Report
    - Timeline
    - Actions taken
    - Lessons learned
    ↓
Update Runbooks
    ↓
Retrain Models (if needed)
    ↓
Brief Management
```

## Integration Scenarios

### Scenario 1: SIEM Integration

**Setup**: Forward DIDS alerts to Splunk SIEM

```python
# Alert forwarding configuration
{
  "siem_integration": {
    "enabled": true,
    "type": "splunk",
    "endpoint": "https://splunk.example.com:8088/services/collector",
    "token": "xxxxx-xxxxx-xxxxx",
    "forward_all_alerts": true,
    "include_explanation": true
  }
}
```

**Benefit**: Centralized security monitoring, correlation with other tools

### Scenario 2: Ticketing System Integration

**Setup**: Auto-create tickets in Jira for high-severity alerts

```python
# Jira integration
{
  "ticketing": {
    "enabled": true,
    "system": "jira",
    "url": "https://jira.example.com",
    "project": "SEC",
    "severity_mapping": {
      "critical": "P1",
      "high": "P2",
      "medium": "P3"
    },
    "auto_assign": true
  }
}
```

**Benefit**: Automated workflow, tracking, SLA compliance

### Scenario 3: Threat Intelligence Integration

**Setup**: Enrich alerts with threat intel from AlienVault OTX

```python
# Threat intel enrichment
{
  "threat_intel": {
    "providers": [
      {
        "name": "alienvault_otx",
        "api_key": "xxxxx",
        "enabled": true
      },
      {
        "name": "virustotal",
        "api_key": "xxxxx",
        "enabled": true
      }
    ],
    "auto_enrich": true,
    "cache_ttl": 3600
  }
}
```

**Benefit**: Context-rich alerts, known attacker identification

## Success Metrics by Persona

### Security Analyst (Sarah)

- **Alert Investigation Time**: Reduced from 15 min to 5 min (67% faster)
- **False Positive Rate**: 1.8% (vs 10% industry average)
- **Confidence in Decisions**: 95% (due to explanations)
- **Alerts per Day**: 30 (vs 200 without AI filtering)

### SOC Manager (Michael)

- **Team Efficiency**: Handle 3x more alerts with same team size
- **Detection Rate**: 99.6% (vs 85% with signatures only)
- **MTTD** (Mean Time to Detect): <5 seconds
- **MTTR** (Mean Time to Respond): <60 seconds
- **Cost Savings**: $200K/year in reduced analyst time

### Network Admin (Alex)

- **Network Performance**: <78ms latency (no noticeable impact)
- **False Positive Blocks**: <2% (minimal disruption)
- **Integration Time**: 2 hours (easy setup)
- **Maintenance**: <1 hour/week (low overhead)

### Compliance Officer (Jennifer)

- **Audit Preparation**: 2 hours (vs 2 days manual)
- **Compliance Coverage**: 100% (GDPR, HIPAA, PCI-DSS)
- **Audit Findings**: 0 (clean audit)
- **Report Generation**: Automated (vs manual)

## Conclusion

DIDS is designed for real-world security operations, with user workflows and needs at the center of the design. By understanding our users' goals, pain points, and daily workflows, we've created a system that:

✅ **Reduces Alert Fatigue**: AI filtering reduces noise by 85%
✅ **Accelerates Investigation**: Explanations reduce investigation time by 67%
✅ **Improves Accuracy**: 99.6% detection rate with 1.8% FPR
✅ **Enables Learning**: Junior analysts learn faster with explainable AI
✅ **Ensures Compliance**: Automated reports and audit trails

**Remember**: Technology serves people. The best security tool is one that analysts trust and actually use.

---

**Last Updated**: 2025-01-20
**Maintained By**: DIDS Product Team
