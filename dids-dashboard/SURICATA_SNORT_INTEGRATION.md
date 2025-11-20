# Suricata/Snort Integration Documentation

## Overview

The DIDS (Distributed Intrusion Detection System) now includes full support for Suricata and Snort IDS rules, allowing you to leverage existing community and commercial rule sets for real-time threat detection.

## Features

- **Full Rule Parser**: Parses Suricata/Snort rule syntax including all major options
- **Real-time Packet Matching**: Matches network packets against loaded rules in real-time
- **MongoDB Storage**: All rules are stored in MongoDB with full indexing
- **REST API**: Complete API for rule management (CRUD operations)
- **Rule Statistics**: Track rule hits, effectiveness, and performance
- **Multiple Rule Sources**: Load rules from files, strings, or API uploads
- **Rule Management**: Enable/disable rules dynamically without restart

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Packet Capture Layer                      │
│                  (Scapy-based capture)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Threat Detection Layer                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Suricata/   │  │  Built-in    │  │  AI/ML       │      │
│  │  Snort Rules │  │  Signatures  │  │  Detection   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              Alert & Response Management                     │
│           (MongoDB + REST API + Dashboard)                   │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Rule Parser (`services/rule_parser.py`)

Parses Suricata/Snort rule format:
```
alert tcp any any -> any 80 (msg:"ET WEB SQL Injection"; content:"UNION SELECT"; sid:1000001; rev:1;)
```

**Supported Rule Components:**
- Actions: `alert`, `log`, `pass`, `drop`, `reject`, `sdrop`
- Protocols: `tcp`, `udp`, `icmp`, `ip`, `http`, `dns`, `ssh`, `ftp`, `tls`, `smb`
- IP Addresses: Single IPs, CIDR notation, ranges, `any`, variables (`$HOME_NET`)
- Ports: Single ports, ranges (`:1024`), port lists (`[80,443,8080]`), variables (`$HTTP_PORTS`)
- Direction: `->`, `<>`, `<-`

**Supported Options:**
- `msg`: Rule message/description
- `sid`: Signature ID
- `rev`: Revision number
- `priority`: 1-4 (1=critical, 4=low)
- `classtype`: Attack classification
- `content`: Pattern matching in payload
- `pcre`: Perl-compatible regex
- `flags`: TCP flag matching
- `flow`: Flow direction and state
- `threshold`: Event threshold/rate limiting
- `reference`: External references (CVE, URLs)

### 2. Rule Engine (`services/rule_engine.py`)

Matches packets against loaded rules in real-time.

**Matching Capabilities:**
- IP address matching (exact, CIDR, ranges, negation)
- Port matching (exact, ranges, lists, negation)
- Bidirectional rule support
- Content pattern matching (hex and string)
- PCRE regex matching
- TCP flag matching
- Flow direction analysis

**Performance:**
- Efficient indexing by protocol
- Rule caching
- Incremental hit counting

### 3. Rule Manager (`services/rule_parser.py`)

Manages rule lifecycle and storage.

**Features:**
- Load rules from files
- Load rules from strings/API
- Store rules in MongoDB
- Enable/disable rules
- Track rule statistics
- Get top triggered rules

### 4. MongoDB Schema (`database/schemas.py`)

Complete schema for rules collection with validation and indexing.

**Indexes:**
- `sid` (unique)
- `enabled`, `severity`, `protocol`, `action`
- `hit_count` (descending)
- `last_hit` (descending)
- `classtype`

## API Endpoints

All endpoints are under `/api/v1/rules` and require authentication.

### Get All Rules
```bash
GET /api/v1/rules
GET /api/v1/rules?protocol=tcp
GET /api/v1/rules?severity=critical
GET /api/v1/rules?enabled=true
GET /api/v1/rules?search=sql
```

**Response:**
```json
{
  "total": 50,
  "rules": [...],
  "timestamp": "2025-01-20T10:30:00"
}
```

### Get Specific Rule
```bash
GET /api/v1/rules/{sid}
```

**Response:**
```json
{
  "sid": "1000001",
  "msg": "ET WEB SQL Injection Attempt",
  "action": "alert",
  "protocol": "tcp",
  "severity": "high",
  "enabled": true,
  "hit_count": 42,
  "last_hit": "2025-01-20T10:29:30",
  ...
}
```

### Create Rule
```bash
POST /api/v1/rules
Content-Type: application/json

{
  "rule": "alert tcp any any -> any 80 (msg:\"Test Rule\"; sid:9999999; rev:1;)"
}
```

### Create Multiple Rules
```bash
POST /api/v1/rules/bulk
Content-Type: application/json

{
  "rules": [
    "alert tcp any any -> any 80 (msg:\"Rule 1\"; sid:9999991; rev:1;)",
    "alert tcp any any -> any 443 (msg:\"Rule 2\"; sid:9999992; rev:1;)"
  ]
}
```

### Upload Rule File
```bash
POST /api/v1/rules/upload
Content-Type: multipart/form-data

file: emerging-threats.rules
```

### Enable/Disable Rule
```bash
POST /api/v1/rules/{sid}/enable
POST /api/v1/rules/{sid}/disable

# Or use PUT
PUT /api/v1/rules/{sid}
Content-Type: application/json

{
  "enabled": false
}
```

### Delete Rule (Disables)
```bash
DELETE /api/v1/rules/{sid}
```

### Get Rule Statistics
```bash
GET /api/v1/rules/statistics
```

**Response:**
```json
{
  "total_loaded": 50,
  "active_rules": 45,
  "disabled_rules": 5,
  "total_hits": 1523,
  "by_severity": {
    "critical": 10,
    "high": 15,
    "medium": 20,
    "low": 5
  },
  "by_protocol": {
    "tcp": 35,
    "udp": 10,
    "icmp": 5
  },
  "engine": {
    "total_packets": 150000,
    "total_matches": 1523,
    "match_rate": 1.015
  }
}
```

### Get Top Triggered Rules
```bash
GET /api/v1/rules/top?limit=10
```

**Response:**
```json
{
  "count": 10,
  "rules": [
    {
      "sid": "1000010",
      "msg": "ET WEB SQL Injection Attempt",
      "hit_count": 342,
      "severity": "high",
      "last_hit": "2025-01-20T10:29:30"
    },
    ...
  ]
}
```

### Test Rule Syntax
```bash
POST /api/v1/rules/test
Content-Type: application/json

{
  "rule": "alert tcp any any -> any 80 (msg:\"Test\"; sid:1; rev:1;)",
  "packet": {...}
}
```

## Default Rules

The system comes with 50+ default rules covering:

### Categories:
1. **Malware Detection** (SID 1000001-1000009)
   - Backdoor ports
   - Reverse shells
   - Metasploit payloads

2. **Web Attacks** (SID 1000010-1000039)
   - SQL Injection
   - XSS (Cross-Site Scripting)
   - Directory Traversal
   - Command Injection
   - PHP Code Injection

3. **Scanning & Reconnaissance** (SID 1000040-1000049)
   - SYN FIN scans
   - NULL scans
   - XMAS scans

4. **Network Attacks** (SID 1000050-1000059)
   - SSH brute force
   - FTP brute force
   - RDP connections
   - SMB connections

5. **DNS Attacks** (SID 1000060-1000069)
   - DNS tunneling
   - DNS amplification

6. **Exploit Attempts** (SID 1000070-1000079)
   - Buffer overflows
   - Shellcode detection
   - Format string attacks

7. **Policy Violations** (SID 1000080-1000089)
   - IRC connections
   - Telnet usage
   - Cryptocurrency mining

8. **Data Exfiltration** (SID 1000090-1000099)
   - Large outbound transfers
   - Base64 encoded data

9. **Botnet Activity** (SID 1000100-1000109)
   - C2 beacons
   - IRC bot commands

10. **Vulnerability Scans** (SID 1000110-1000119)
    - Nmap detection
    - Nessus detection
    - OpenVAS detection

## Usage Examples

### Loading Custom Rules via CLI

```python
from services.rule_parser import RuleManager
from services.rule_engine import RuleEngine

# Initialize
rule_manager = RuleManager(db=mongo.db)
rule_engine = RuleEngine(rule_manager)

# Load from file
rules_loaded = rule_manager.load_rules_from_file('/path/to/custom.rules')
print(f"Loaded {rules_loaded} rules")

# Load from strings
custom_rules = [
    'alert tcp any any -> any 8080 (msg:"Custom Rule 1"; sid:5000001; rev:1;)',
    'alert udp any any -> any 53 (msg:"Custom DNS Rule"; sid:5000002; rev:1;)'
]
rules_loaded = rule_manager.load_rules_from_strings(custom_rules)
```

### Matching Packets

```python
# Packet info from Scapy
packet_info = {
    'source': '192.168.1.100',
    'destination': '10.0.0.5',
    'protocol': 'TCP',
    'src_port': 54321,
    'dst_port': 80,
    'size': 512
}

# Optional payload
payload = b"GET /admin.php?id=1' OR '1'='1 HTTP/1.1"

# Match against rules
matches = rule_engine.match_packet(packet_info, payload)

for match in matches:
    print(f"Rule matched: {match['rule_msg']} (SID: {match['rule_sid']})")
    print(f"Action: {match['action']}, Severity: {match['severity']}")
```

### Integrating Custom Rule Sources

```python
# Download Emerging Threats rules
import requests

et_url = "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules"
response = requests.get(et_url)

if response.status_code == 200:
    # Save to file
    with open('emerging-threats.rules', 'w') as f:
        f.write(response.text)

    # Load into system
    rules_loaded = rule_manager.load_rules_from_file('emerging-threats.rules')
    print(f"Loaded {rules_loaded} Emerging Threats rules")
```

## Rule Writing Guide

### Basic Rule Structure
```
action protocol src_ip src_port direction dst_ip dst_port (options)
```

### Example: Detect SQL Injection
```
alert tcp any any -> any $HTTP_PORTS (
    msg:"SQL Injection Attempt - UNION SELECT";
    flow:to_server;
    content:"UNION"; nocase;
    content:"SELECT"; nocase; distance:0;
    classtype:web-application-attack;
    sid:1000010;
    rev:1;
    priority:2;
)
```

### Example: Detect SSH Brute Force
```
alert tcp any any -> any 22 (
    msg:"SSH Brute Force Attempt";
    flags:S;
    threshold:type both, track by_src, count 10, seconds 60;
    classtype:attempted-admin;
    sid:1000050;
    rev:1;
    priority:2;
)
```

### Example: Detect Malware C2 Beacon
```
alert tcp $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Possible Malware C2 Beacon";
    flow:to_server;
    dsize:<100;
    threshold:type both, track by_src, count 20, seconds 60;
    classtype:trojan-activity;
    sid:1000101;
    rev:1;
    priority:1;
)
```

## Performance Considerations

- Rules are indexed by protocol for fast lookup
- Only active rules are evaluated
- Regex patterns are compiled once and cached
- Rule statistics are updated incrementally
- MongoDB provides efficient rule storage and retrieval

## Limitations

- Some Suricata-specific options may not be fully supported
- Stateful tracking is basic (based on port numbers)
- Threshold tracking is simplified
- No rule preprocessing/optimization (yet)

## Future Enhancements

- [ ] Full stateful connection tracking
- [ ] Advanced threshold mechanisms
- [ ] Rule performance profiling
- [ ] Automatic rule updates from community sources
- [ ] Rule testing harness
- [ ] Rule conflict detection
- [ ] Custom action handlers
- [ ] Integration with response/blocking mechanisms

## Troubleshooting

### Rules Not Loading
- Check rule syntax with `/api/v1/rules/test`
- Verify file permissions for rule files
- Check MongoDB connection
- Review application logs

### Low Match Rate
- Verify rules are enabled
- Check protocol filters
- Ensure packet capture is working
- Review rule specificity

### Performance Issues
- Reduce number of active rules
- Disable low-priority rules
- Use more specific IP/port filters
- Consider rule optimization

## Support

For issues or questions:
- Check application logs: `/var/log/dids/app.log`
- Review rule statistics: `GET /api/v1/rules/statistics`
- Test rules: `POST /api/v1/rules/test`
- Consult Suricata/Snort documentation for rule syntax

## References

- [Suricata Rules Documentation](https://suricata.readthedocs.io/en/latest/rules/)
- [Snort Rules Documentation](https://www.snort.org/documents)
- [Emerging Threats Rules](https://rules.emergingthreats.net/)
- [Suricata Rule Format](https://suricata.readthedocs.io/en/latest/rules/intro.html)
