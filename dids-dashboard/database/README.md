# DIDS Dashboard - MongoDB Database Schema

Complete MongoDB schema definitions for all collections with validation rules and indexes.

## Collections

### 1. Packets Collection
Stores captured network packets with extracted features.

**Key Fields:**
- `timestamp`: Packet capture time
- `source`, `destination`: IP addresses
- `protocol`: Network protocol (TCP, UDP, ICMP, etc.)
- `src_port`, `dst_port`: Port numbers
- `size`: Packet size in bytes
- `tcp_flags`: TCP flags (SYN, ACK, FIN, etc.)
- `flow_id`: Associated flow identifier
- `is_threat`: Threat flag
- `features`: Extracted features for ML/RL

**Indexes:**
- `timestamp` (descending) - Recent packets
- `source + timestamp` - Source-based queries
- `destination + timestamp` - Destination-based queries
- `protocol + timestamp` - Protocol filtering
- `flow_id` - Flow association
- `is_threat + timestamp` - Threat filtering
- TTL index: 7 days retention

### 2. Threats Collection
Stores detected security threats.

**Key Fields:**
- `timestamp`: Detection time
- `source`, `destination`: IP addresses
- `threat_type`: Type (DDoS, PortScan, BruteForce, etc.)
- `severity`: critical, high, medium, low
- `signature`: Detection signature rule
- `confidence`: Detection confidence (0-100%)
- `action`: allow, alert, block
- `detector`: signature, ai, rl, hybrid
- `blocked`: Whether threat was blocked

**Indexes:**
- `timestamp` (descending)
- `severity + timestamp`
- `threat_type + timestamp`
- `source + timestamp`
- `detector + timestamp`
- `action + timestamp`

### 3. Detections Collection
Stores detailed detection results from AI/RL/Signature detectors.

**Key Fields:**
- `timestamp`: Detection time
- `detector_type`: signature, ai, rl
- `packet_data`: Analyzed packet data
- `result`: Detection result with confidence
- `ai_prediction`: ML model prediction details
- `rl_decision`: RL agent decision with Q-values
- `signature_matches`: Matched signatures
- `processing_time_ms`: Detection latency

**Indexes:**
- `timestamp` (descending)
- `detector_type + timestamp`
- `result.is_threat + timestamp`
- TTL index: 30 days retention

### 4. Flows Collection
Stores network flow aggregations.

**Key Fields:**
- `flow_id`: Unique flow identifier
- `source`, `destination`: IP addresses
- `start_time`, `last_seen`: Flow timestamps
- `duration`: Flow duration in seconds
- `packet_count`: Total packets
- `total_bytes`: Total bytes transferred
- `forward_packets`, `backward_packets`: Directional stats
- `features`: 77 flow features for ML/RL
- `is_threat`: Threat flag
- `status`: active, closed, timeout

**Indexes:**
- `flow_id` (unique)
- `start_time` (descending)
- `source + destination + start_time`
- `status + last_seen`
- `is_threat + start_time`
- TTL index: 7 days retention

### 5. Alerts Collection
Stores security alerts and notifications.

**Key Fields:**
- `timestamp`: Alert time
- `severity`: critical, high, medium, low, info
- `type`: Alert type
- `message`: Alert message
- `action`: Action taken
- `threat_id`: Reference to threat
- `read`, `acknowledged`: Status flags
- `acknowledged_by`, `acknowledged_at`: Acknowledgement info

**Indexes:**
- `timestamp` (descending)
- `severity + timestamp`
- `type + timestamp`
- `read + timestamp`
- `acknowledged + timestamp`

### 6. Users Collection
Stores user accounts and authentication.

**Key Fields:**
- `username`: Unique username (3-50 chars)
- `password_hash`: Bcrypt hashed password
- `full_name`, `email`: User details
- `role`: admin, analyst, viewer, user
- `active`: Account status
- `created_at`, `last_login`: Timestamps
- `failed_login_attempts`: Failed login count
- `locked_until`: Account lock expiration
- `preferences`: User settings

**Indexes:**
- `username` (unique)
- `email` (unique, sparse)
- `role`
- `active`

### 7. Statistics Collection
Stores aggregated system statistics.

**Key Fields:**
- `timestamp`: Collection time
- `metric_type`: traffic, threats, detections, system, performance
- `period`: minute, hour, day, week, month
- `traffic_stats`: Traffic metrics
- `threat_stats`: Threat metrics
- `detection_stats`: Detection metrics
- `system_stats`: System health metrics
- `performance_stats`: Performance metrics

**Indexes:**
- `timestamp` (descending)
- `metric_type + timestamp`
- `period + timestamp`
- TTL index: 90 days retention

### 8. System Logs Collection
Stores system logs and audit trail.

**Key Fields:**
- `timestamp`: Log time
- `level`: DEBUG, INFO, WARNING, ERROR, CRITICAL
- `component`: Service/module name
- `message`: Log message
- `user`: Associated user
- `action`: Action performed
- `ip_address`: IP if applicable
- `error_details`: Error stack trace
- `metadata`: Additional data

**Indexes:**
- `timestamp` (descending)
- `level + timestamp`
- `component + timestamp`
- `user + timestamp`
- TTL index: 30 days retention

## Schema Validation

All collections use MongoDB JSON Schema validation to ensure data integrity:

- **Type validation**: Ensures correct BSON types
- **Range validation**: Validates numeric ranges (ports: 0-65535, confidence: 0-100)
- **Enum validation**: Restricts values to predefined sets
- **Pattern validation**: Validates IP addresses, email formats
- **Required fields**: Enforces mandatory fields

## Indexes

Optimized indexes for common query patterns:

- **Time-series queries**: All collections indexed on `timestamp` descending
- **Compound indexes**: Multi-field indexes for common filter combinations
- **Unique indexes**: Prevent duplicates (flow_id, username, email)
- **TTL indexes**: Automatic data expiration for time-limited data

## Data Retention

Automatic cleanup via TTL indexes:

- **Packets**: 7 days
- **Detections**: 30 days
- **Flows**: 7 days (based on last_seen)
- **Statistics**: 90 days
- **System Logs**: 30 days
- **Threats, Alerts, Users**: No automatic expiration

## Usage

### Initialize Database

```python
from flask_pymongo import PyMongo
from database import init_database, create_indexes

# Initialize Flask-PyMongo
mongo = PyMongo(app)

# Initialize all collections with schemas
results = init_database(mongo.db)
print("Database initialization:", results)

# Create indexes
index_results = create_indexes(mongo.db)
print("Index creation:", index_results)
```

### Using Database Helper

```python
from database.utils import DatabaseHelper

# Initialize helper
db_helper = DatabaseHelper(mongo.db)

# Insert packet
packet_id = db_helper.insert_packet({
    'source': '192.168.1.100',
    'destination': '8.8.8.8',
    'protocol': 'TCP',
    'size': 1024,
    'is_threat': False
})

# Get recent threats
threats = db_helper.get_recent_threats(limit=20, severity='critical')

# Insert alert
alert_id = db_helper.insert_alert({
    'severity': 'high',
    'type': 'Port Scan',
    'message': 'Port scan detected from 192.168.1.50',
    'source': '192.168.1.50'
})

# Get statistics
stats = db_helper.get_threat_statistics(hours=24)
```

### Manual Schema Update

If you need to update schemas on existing collections:

```python
from database import init_database

# Update schemas without dropping data
results = init_database(mongo.db, drop_existing=False)
```

## Performance Considerations

1. **Index Usage**: All time-based queries use descending indexes
2. **Compound Indexes**: Multi-field filters use compound indexes
3. **Projection**: Limit fields returned in queries
4. **Aggregation**: Use aggregation pipelines for complex statistics
5. **TTL Indexes**: Automatic cleanup prevents unbounded growth
6. **Sparse Indexes**: Email index is sparse (not all users have email)

## Security

1. **Password Hashing**: Passwords stored as bcrypt hashes
2. **Validation**: JSON Schema prevents malformed data
3. **Audit Logging**: All actions logged in system_logs
4. **User Locking**: Failed login attempts trigger account locks
5. **Role-Based Access**: User roles control permissions

## Backup and Recovery

Recommended backup strategy:

```bash
# Backup entire database
mongodump --db dids_dashboard --out /backup/$(date +%Y%m%d)

# Backup specific collection
mongodump --db dids_dashboard --collection threats --out /backup/threats

# Restore database
mongorestore --db dids_dashboard /backup/20251120/dids_dashboard
```

## Monitoring

Monitor collection statistics:

```python
from database.schemas import get_collection_stats

stats = get_collection_stats(mongo.db)
for collection, info in stats.items():
    print(f"{collection}: {info['count']} documents, {info['indexes']} indexes")
```

## Migration

For schema changes in production:

1. Test schema changes in development/staging
2. Backup production database
3. Apply schema updates during maintenance window
4. Verify data integrity
5. Monitor for validation errors

## Troubleshooting

### Validation Errors

If documents fail validation:

```python
# Check validation errors
try:
    mongo.db.packets.insert_one(invalid_packet)
except Exception as e:
    print(f"Validation error: {e}")
```

### Index Issues

If queries are slow:

```bash
# Check query plan
db.packets.find({...}).explain()

# List all indexes
db.packets.getIndexes()
```

### Disk Space

Monitor collection sizes:

```python
stats = get_collection_stats(mongo.db)
total_size = sum(s.get('size_bytes', 0) for s in stats.values())
print(f"Total database size: {total_size / 1024 / 1024:.2f} MB")
```

## References

- [MongoDB JSON Schema Validation](https://docs.mongodb.com/manual/core/schema-validation/)
- [MongoDB Indexes](https://docs.mongodb.com/manual/indexes/)
- [MongoDB TTL Indexes](https://docs.mongodb.com/manual/core/index-ttl/)
- [PyMongo Documentation](https://pymongo.readthedocs.io/)
