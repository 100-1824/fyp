# Data Handling and Versioning Strategy

## Overview

This document outlines the comprehensive data management strategy for DIDS, covering data collection, preprocessing, storage, versioning, and lifecycle management. Proper data management is critical for model accuracy, reproducibility, and compliance.

## Table of Contents

1. [Data Types and Sources](#data-types-and-sources)
2. [Data Collection](#data-collection)
3. [Data Preprocessing](#data-preprocessing)
4. [Data Storage](#data-storage)
5. [Data Versioning](#data-versioning)
6. [Dataset Management](#dataset-management)
7. [Model Versioning](#model-versioning)
8. [Data Lifecycle](#data-lifecycle)
9. [Privacy and Compliance](#privacy-and-compliance)
10. [Backup and Recovery](#backup-and-recovery)

## Data Types and Sources

### 1. Training Data

| Dataset | Source | Size | Purpose | Format |
|---------|--------|------|---------|--------|
| **CICIDS2017** | Canadian Institute for Cybersecurity | 2.8M samples | Primary training | CSV/Parquet |
| **NSL-KDD** | UNB | 150K samples | Validation | CSV |
| **Production Logs** | Live traffic | Growing | Continuous learning | JSON/Parquet |

### 2. Operational Data

```
Network Traffic
├── Raw Packets (PCAP)
├── Flow Records (NetFlow)
├── Feature Vectors (42 features)
└── Metadata (timestamps, IPs, protocols)

Alerts
├── Alert Records
├── Human Feedback
├── False Positive/Negative Labels
└── Analyst Notes

System Metrics
├── Performance Metrics
├── Resource Utilization
├── Model Metrics (accuracy, latency)
└── Audit Logs
```

### 3. Model Artifacts

```
Models/
├── Trained Models (.keras, .h5)
├── Checkpoints (training snapshots)
├── Model Metadata (hyperparameters, metrics)
├── Feature Scalers (StandardScaler, MinMaxScaler)
└── Training History (loss, accuracy curves)
```

## Data Collection

### Training Data Collection

```python
# ml-training/data_collection/dataset_loader.py

class DatasetLoader:
    """Load and manage training datasets"""

    def __init__(self, data_dir='ml-training/data/raw'):
        self.data_dir = data_dir
        self.datasets = {}

    def load_cicids2017(self):
        """Load CICIDS2017 dataset"""

        files = [
            'Monday-WorkingHours.pcap_ISCX.csv',
            'Tuesday-WorkingHours.pcap_ISCX.csv',
            'Wednesday-workingHours.pcap_ISCX.csv',
            'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
            'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
            'Friday-WorkingHours-Morning.pcap_ISCX.csv',
            'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
            'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'
        ]

        dataframes = []
        for file in files:
            path = os.path.join(self.data_dir, 'CICIDS2017', file)
            df = pd.read_csv(path)

            # Add source metadata
            df['source_file'] = file
            df['dataset'] = 'CICIDS2017'
            df['collection_date'] = self._extract_date_from_filename(file)

            dataframes.append(df)

        # Combine all files
        combined = pd.concat(dataframes, ignore_index=True)

        # Add dataset version
        combined['dataset_version'] = '1.0.0'

        self.datasets['CICIDS2017'] = combined
        return combined

    def load_nsl_kdd(self):
        """Load NSL-KDD dataset"""

        train_path = os.path.join(self.data_dir, 'NSL-KDD', 'KDDTrain+.txt')
        test_path = os.path.join(self.data_dir, 'NSL-KDD', 'KDDTest+.txt')

        # Load with column names
        columns = [
            'duration', 'protocol_type', 'service', 'flag',
            'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
            # ... (41 total columns)
            'label', 'difficulty'
        ]

        train_df = pd.read_csv(train_path, names=columns)
        test_df = pd.read_csv(test_path, names=columns)

        train_df['split'] = 'train'
        test_df['split'] = 'test'

        combined = pd.concat([train_df, test_df], ignore_index=True)
        combined['dataset'] = 'NSL-KDD'
        combined['dataset_version'] = '1.0.0'

        self.datasets['NSL-KDD'] = combined
        return combined

    def verify_dataset_integrity(self, dataset_name):
        """Verify dataset integrity with checksums"""

        df = self.datasets[dataset_name]

        checks = {
            'null_values': df.isnull().sum().sum(),
            'duplicate_rows': df.duplicated().sum(),
            'negative_values': (df.select_dtypes(include=[np.number]) < 0).sum().sum(),
            'inf_values': np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
        }

        if any(checks.values()):
            warnings.warn(f"Dataset integrity issues found: {checks}")

        return checks
```

### Live Traffic Collection

```python
# traffic-capture/capture.py

class TrafficCapture:
    """Capture live network traffic for training"""

    def __init__(self, interface='eth0', output_dir='/data/raw'):
        self.interface = interface
        self.output_dir = output_dir
        self.buffer = []

    def start_capture(self, duration_hours=24):
        """Capture traffic for specified duration"""

        # Rotate capture files every hour
        rotation_interval = 3600  # seconds

        start_time = time.time()
        end_time = start_time + (duration_hours * 3600)

        while time.time() < end_time:
            # Capture for rotation interval
            pcap_file = self._generate_pcap_filename()

            sniff(
                iface=self.interface,
                prn=self.process_packet,
                timeout=rotation_interval,
                store=False
            )

            # Save buffer to file
            self._save_buffer(pcap_file)
            self.buffer = []

    def process_packet(self, packet):
        """Extract features from packet"""

        features = extract_features(packet)

        # Add metadata
        features['capture_timestamp'] = time.time()
        features['interface'] = self.interface
        features['capture_version'] = '1.0.0'

        self.buffer.append(features)

    def _save_buffer(self, filename):
        """Save captured data to Parquet"""

        df = pd.DataFrame(self.buffer)

        # Save as Parquet (compressed, efficient)
        output_path = os.path.join(self.output_dir, filename)
        df.to_parquet(
            output_path,
            compression='snappy',
            index=False
        )

        log.info(f"Saved {len(self.buffer)} packets to {output_path}")
```

## Data Preprocessing

### Preprocessing Pipeline

```python
# ml-training/preprocessing/pipeline.py

class PreprocessingPipeline:
    """Complete preprocessing pipeline"""

    def __init__(self, config_path='config/preprocessing.yaml'):
        self.config = load_config(config_path)
        self.scaler = None
        self.encoder = None

    def fit_transform(self, df, save_artifacts=True):
        """
        Fit preprocessing pipeline and transform data

        Steps:
        1. Handle missing values
        2. Remove duplicates
        3. Encode categorical features
        4. Scale numerical features
        5. Handle class imbalance
        6. Split train/val/test
        """

        # 1. Handle missing values
        df = self._handle_missing_values(df)

        # 2. Remove duplicates
        df = df.drop_duplicates()

        # 3. Separate features and labels
        X = df.drop(columns=['Label'])
        y = df['Label']

        # 4. Encode categorical features
        X_encoded, self.encoder = self._encode_categorical(X)

        # 5. Scale numerical features
        X_scaled, self.scaler = self._scale_features(X_encoded)

        # 6. Handle class imbalance
        X_balanced, y_balanced = self._balance_classes(X_scaled, y)

        # 7. Split data
        X_train, X_val, X_test, y_train, y_val, y_test = self._split_data(
            X_balanced, y_balanced
        )

        # Save preprocessing artifacts
        if save_artifacts:
            self._save_artifacts()

        return {
            'train': (X_train, y_train),
            'val': (X_val, y_val),
            'test': (X_test, y_test)
        }

    def _handle_missing_values(self, df):
        """Handle missing values"""

        # Strategy depends on column
        for col in df.columns:
            if df[col].isnull().sum() > 0:
                if df[col].dtype == 'object':
                    # Categorical: fill with mode
                    df[col].fillna(df[col].mode()[0], inplace=True)
                else:
                    # Numerical: fill with median
                    df[col].fillna(df[col].median(), inplace=True)

        return df

    def _encode_categorical(self, X):
        """Encode categorical features"""

        from sklearn.preprocessing import LabelEncoder

        encoder = {}
        X_encoded = X.copy()

        categorical_cols = X.select_dtypes(include=['object']).columns

        for col in categorical_cols:
            le = LabelEncoder()
            X_encoded[col] = le.fit_transform(X[col])
            encoder[col] = le

        return X_encoded, encoder

    def _scale_features(self, X):
        """Scale features to [0, 1]"""

        from sklearn.preprocessing import StandardScaler

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        return X_scaled, scaler

    def _balance_classes(self, X, y):
        """Balance classes using SMOTE"""

        from imblearn.over_sampling import SMOTE

        # Check class distribution
        class_counts = Counter(y)
        log.info(f"Original class distribution: {class_counts}")

        # Apply SMOTE only if imbalanced
        minority_ratio = min(class_counts.values()) / max(class_counts.values())

        if minority_ratio < 0.5:
            smote = SMOTE(random_state=42)
            X_balanced, y_balanced = smote.fit_resample(X, y)

            log.info(f"Balanced class distribution: {Counter(y_balanced)}")
            return X_balanced, y_balanced

        return X, y

    def _split_data(self, X, y, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15):
        """Split data into train/val/test"""

        from sklearn.model_selection import train_test_split

        # First split: train vs (val + test)
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y,
            test_size=(val_ratio + test_ratio),
            random_state=42,
            stratify=y
        )

        # Second split: val vs test
        val_size = val_ratio / (val_ratio + test_ratio)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp,
            test_size=(1 - val_size),
            random_state=42,
            stratify=y_temp
        )

        log.info(f"Split sizes - Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

        return X_train, X_val, X_test, y_train, y_val, y_test

    def _save_artifacts(self):
        """Save preprocessing artifacts"""

        artifact_dir = 'ml-training/artifacts/preprocessing/v1.0.0'
        os.makedirs(artifact_dir, exist_ok=True)

        # Save scaler
        joblib.dump(self.scaler, f'{artifact_dir}/scaler.pkl')

        # Save encoder
        joblib.dump(self.encoder, f'{artifact_dir}/encoder.pkl')

        # Save config
        with open(f'{artifact_dir}/config.yaml', 'w') as f:
            yaml.dump(self.config, f)

        log.info(f"Saved preprocessing artifacts to {artifact_dir}")

    def transform(self, df):
        """Transform new data using fitted pipeline"""

        if self.scaler is None or self.encoder is None:
            raise ValueError("Pipeline not fitted. Call fit_transform() first.")

        # Apply same preprocessing steps
        df = self._handle_missing_values(df)

        X = df.drop(columns=['Label'], errors='ignore')

        # Encode categorical
        X_encoded = X.copy()
        for col, encoder in self.encoder.items():
            if col in X_encoded.columns:
                X_encoded[col] = encoder.transform(X[col])

        # Scale numerical
        X_scaled = self.scaler.transform(X_encoded)

        return X_scaled
```

### Data Quality Checks

```python
# ml-training/data_validation/quality_checks.py

class DataQualityChecker:
    """Validate data quality"""

    def run_checks(self, df):
        """Run all quality checks"""

        results = {
            'completeness': self._check_completeness(df),
            'consistency': self._check_consistency(df),
            'validity': self._check_validity(df),
            'timeliness': self._check_timeliness(df),
            'accuracy': self._check_accuracy(df)
        }

        # Overall pass/fail
        results['passed'] = all([
            check['passed'] for check in results.values()
        ])

        return results

    def _check_completeness(self, df):
        """Check for missing values"""

        missing_pct = df.isnull().sum().sum() / (df.shape[0] * df.shape[1])

        return {
            'metric': 'completeness',
            'value': 1 - missing_pct,
            'threshold': 0.95,
            'passed': (1 - missing_pct) >= 0.95,
            'message': f"{missing_pct:.2%} missing values"
        }

    def _check_consistency(self, df):
        """Check for inconsistent values"""

        issues = []

        # Check: packet length should be positive
        if (df['packet_length'] < 0).any():
            issues.append("Negative packet lengths found")

        # Check: timestamps should be ordered
        if not df['timestamp'].is_monotonic_increasing:
            issues.append("Timestamps not in order")

        return {
            'metric': 'consistency',
            'issues': issues,
            'passed': len(issues) == 0,
            'message': f"{len(issues)} consistency issues"
        }

    def _check_validity(self, df):
        """Check value ranges"""

        issues = []

        # Check: IP addresses should be valid
        # Check: Ports should be 0-65535
        if (df['dst_port'] < 0).any() or (df['dst_port'] > 65535).any():
            issues.append("Invalid port numbers")

        return {
            'metric': 'validity',
            'issues': issues,
            'passed': len(issues) == 0,
            'message': f"{len(issues)} validity issues"
        }

    def _check_timeliness(self, df):
        """Check data freshness"""

        if 'timestamp' not in df.columns:
            return {'metric': 'timeliness', 'passed': True, 'message': 'N/A'}

        latest_timestamp = df['timestamp'].max()
        age_days = (time.time() - latest_timestamp) / 86400

        return {
            'metric': 'timeliness',
            'value': age_days,
            'threshold': 7,  # Data should be < 7 days old
            'passed': age_days < 7,
            'message': f"Data is {age_days:.1f} days old"
        }

    def _check_accuracy(self, df):
        """Check label accuracy (if ground truth available)"""

        # Placeholder: would compare with ground truth
        return {
            'metric': 'accuracy',
            'passed': True,
            'message': 'Manual validation required'
        }
```

## Data Storage

### Storage Architecture

```
Data Storage Hierarchy:

1. Hot Storage (Fast Access, Expensive)
   ├── Redis: Real-time features, recent alerts
   ├── MongoDB: Recent alerts (7 days), user data
   └── Local SSD: Model checkpoints, current training data

2. Warm Storage (Moderate Access, Moderate Cost)
   ├── MongoDB: Historical alerts (30 days)
   └── Azure Blob: Recent PCAP files (30 days)

3. Cold Storage (Archival, Cheap)
   ├── Azure Blob (Cool Tier): Old PCAP files (>30 days)
   ├── Azure Archive: Compliance data (>1 year)
   └── S3 Glacier: Long-term backups
```

### Storage Configuration

```yaml
# config/storage.yaml

storage:
  # Hot storage (real-time)
  redis:
    host: redis.dids.local
    port: 6379
    ttl_seconds: 604800  # 7 days
    max_memory: 16gb
    eviction_policy: allkeys-lru

  # Warm storage (recent)
  mongodb:
    host: mongodb.dids.local
    port: 27017
    database: dids
    collections:
      alerts:
        retention_days: 30
        indexes:
          - timestamp: -1
          - severity: 1
          - src_ip: 1
      training_data:
        retention_days: 90
        indexes:
          - dataset_version: 1
          - timestamp: -1

  # Cold storage (archive)
  azure_blob:
    account: didsstorage
    containers:
      raw_pcap:
        tier: cool
        retention_days: 365
      training_datasets:
        tier: hot
        retention_days: -1  # Keep forever
      models:
        tier: hot
        retention_days: -1
      backups:
        tier: archive
        retention_days: 2555  # 7 years

  # Local storage
  local:
    data_dir: /mnt/data
    models_dir: /mnt/models
    temp_dir: /tmp/dids
    max_size_gb: 500
```

## Data Versioning

### DVC (Data Version Control)

```bash
# Initialize DVC
cd /home/user/fyp
dvc init

# Track dataset with DVC
dvc add ml-training/data/raw/CICIDS2017.csv
git add ml-training/data/raw/CICIDS2017.csv.dvc .gitignore
git commit -m "Track CICIDS2017 dataset with DVC"

# Push to remote storage
dvc remote add -d azure azure://didsstorage/dvc-storage
dvc push
```

### Dataset Versioning Schema

```python
# ml-training/versioning/dataset_version.py

class DatasetVersion:
    """Manage dataset versions"""

    def __init__(self, name, version):
        self.name = name
        self.version = version  # Semantic versioning: MAJOR.MINOR.PATCH

    @property
    def full_name(self):
        return f"{self.name}_v{self.version}"

    def create_version(self, data, metadata):
        """Create new dataset version"""

        version_dir = f"ml-training/data/versions/{self.full_name}"
        os.makedirs(version_dir, exist_ok=True)

        # Save data
        data.to_parquet(f"{version_dir}/data.parquet", compression='snappy')

        # Save metadata
        metadata_dict = {
            'version': self.version,
            'created_at': datetime.now().isoformat(),
            'num_samples': len(data),
            'columns': list(data.columns),
            'dtypes': {col: str(dtype) for col, dtype in data.dtypes.items()},
            'class_distribution': data['Label'].value_counts().to_dict(),
            'checksum': self._calculate_checksum(data),
            **metadata
        }

        with open(f"{version_dir}/metadata.json", 'w') as f:
            json.dump(metadata_dict, f, indent=2)

        log.info(f"Created dataset version {self.full_name}")

        return version_dir

    def _calculate_checksum(self, data):
        """Calculate SHA256 checksum"""
        import hashlib

        data_bytes = data.to_csv(index=False).encode()
        checksum = hashlib.sha256(data_bytes).hexdigest()

        return checksum

    def load_version(self):
        """Load specific dataset version"""

        version_dir = f"ml-training/data/versions/{self.full_name}"

        # Load data
        data = pd.read_parquet(f"{version_dir}/data.parquet")

        # Load metadata
        with open(f"{version_dir}/metadata.json", 'r') as f:
            metadata = json.load(f)

        # Verify checksum
        checksum = self._calculate_checksum(data)
        if checksum != metadata['checksum']:
            raise ValueError(f"Checksum mismatch for {self.full_name}")

        return data, metadata
```

### Version Naming Convention

```
Dataset Versions:
MAJOR.MINOR.PATCH

MAJOR: Incompatible changes (new features, removed features)
MINOR: Backward-compatible additions (more samples, new labels)
PATCH: Backward-compatible fixes (bug fixes, corrections)

Examples:
v1.0.0: Initial CICIDS2017 dataset
v1.1.0: Added NSL-KDD dataset
v1.1.1: Fixed duplicate rows in CICIDS2017
v2.0.0: Changed feature set from 78 to 42 features
v2.1.0: Added production traffic samples
```

## Dataset Management

### Dataset Registry

```python
# ml-training/registry/dataset_registry.py

class DatasetRegistry:
    """Central registry for all datasets"""

    def __init__(self, registry_path='ml-training/registry/datasets.yaml'):
        self.registry_path = registry_path
        self.registry = self._load_registry()

    def register_dataset(self, name, version, metadata):
        """Register new dataset version"""

        key = f"{name}_v{version}"

        self.registry[key] = {
            'name': name,
            'version': version,
            'registered_at': datetime.now().isoformat(),
            'path': f"ml-training/data/versions/{key}",
            'status': 'active',
            **metadata
        }

        self._save_registry()

        log.info(f"Registered dataset {key}")

    def get_latest_version(self, name):
        """Get latest version of a dataset"""

        versions = [
            v for k, v in self.registry.items()
            if v['name'] == name and v['status'] == 'active'
        ]

        if not versions:
            raise ValueError(f"No active versions found for {name}")

        # Sort by version (semantic versioning)
        latest = max(versions, key=lambda x: version.parse(x['version']))

        return latest

    def deprecate_version(self, name, version):
        """Mark a version as deprecated"""

        key = f"{name}_v{version}"

        if key in self.registry:
            self.registry[key]['status'] = 'deprecated'
            self.registry[key]['deprecated_at'] = datetime.now().isoformat()
            self._save_registry()

            log.info(f"Deprecated dataset {key}")

    def _load_registry(self):
        """Load registry from file"""

        if os.path.exists(self.registry_path):
            with open(self.registry_path, 'r') as f:
                return yaml.safe_load(f) or {}

        return {}

    def _save_registry(self):
        """Save registry to file"""

        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)

        with open(self.registry_path, 'w') as f:
            yaml.dump(self.registry, f, default_flow_style=False)
```

## Model Versioning

### Model Registry

```python
# ml-training/registry/model_registry.py

class ModelRegistry:
    """Manage model versions"""

    def __init__(self, registry_path='ml-training/registry/models.yaml'):
        self.registry_path = registry_path
        self.registry = self._load_registry()

    def register_model(self, name, version, model_path, metrics, metadata):
        """Register trained model"""

        key = f"{name}_v{version}"

        self.registry[key] = {
            'name': name,
            'version': version,
            'registered_at': datetime.now().isoformat(),
            'model_path': model_path,
            'metrics': metrics,
            'status': 'candidate',  # candidate -> production -> archived
            'dataset_version': metadata.get('dataset_version'),
            'hyperparameters': metadata.get('hyperparameters'),
            'training_duration_minutes': metadata.get('training_duration'),
            **metadata
        }

        self._save_registry()

        log.info(f"Registered model {key}")

    def promote_to_production(self, name, version):
        """Promote model to production"""

        key = f"{name}_v{version}"

        # Demote current production model
        for k, v in self.registry.items():
            if v['name'] == name and v['status'] == 'production':
                self.registry[k]['status'] = 'archived'
                self.registry[k]['archived_at'] = datetime.now().isoformat()

        # Promote new model
        self.registry[key]['status'] = 'production'
        self.registry[key]['promoted_at'] = datetime.now().isoformat()

        self._save_registry()

        log.info(f"Promoted {key} to production")

    def get_production_model(self, name):
        """Get current production model"""

        for k, v in self.registry.items():
            if v['name'] == name and v['status'] == 'production':
                return v

        raise ValueError(f"No production model found for {name}")

    def compare_models(self, name, version1, version2, metric='f1_score'):
        """Compare two model versions"""

        key1 = f"{name}_v{version1}"
        key2 = f"{name}_v{version2}"

        model1 = self.registry[key1]
        model2 = self.registry[key2]

        comparison = {
            'model1': {
                'version': version1,
                'metric': model1['metrics'].get(metric),
                'dataset': model1.get('dataset_version')
            },
            'model2': {
                'version': version2,
                'metric': model2['metrics'].get(metric),
                'dataset': model2.get('dataset_version')
            },
            'winner': version1 if model1['metrics'].get(metric) > model2['metrics'].get(metric) else version2
        }

        return comparison
```

### Model Metadata Example

```yaml
# ml-training/registry/models.yaml

anomaly_detection_v1.2.0:
  name: anomaly_detection
  version: 1.2.0
  registered_at: 2025-01-15T10:30:00Z
  promoted_at: 2025-01-20T09:00:00Z
  model_path: dids-dashboard/model/anomaly_detection_v1.2.0.keras
  status: production

  # Training info
  dataset_version: CICIDS2017_v2.1.0
  training_duration_minutes: 245
  training_date: 2025-01-15

  # Performance metrics
  metrics:
    accuracy: 0.973
    precision: 0.968
    recall: 0.979
    f1_score: 0.974
    auc_roc: 0.991
    false_positive_rate: 0.018

  # Hyperparameters
  hyperparameters:
    architecture: CNN_LSTM_hybrid
    learning_rate: 0.001
    batch_size: 64
    epochs: 50
    optimizer: adam
    loss: binary_crossentropy

  # Model artifacts
  artifacts:
    model_file: anomaly_detection_v1.2.0.keras
    scaler: scaler_v1.2.0.pkl
    encoder: encoder_v1.2.0.pkl
    training_history: history_v1.2.0.json

  # Validation
  validated: true
  validation_date: 2025-01-18
  validated_by: ml_team

  # Production info
  deployed_environments:
    - production
    - staging
  deployment_date: 2025-01-20
```

## Data Lifecycle

### Lifecycle Stages

```
Data Lifecycle:

1. Collection
   └─> Raw data from network/datasets

2. Validation
   └─> Quality checks, integrity verification

3. Preprocessing
   └─> Cleaning, feature engineering, scaling

4. Training
   └─> Model training, validation

5. Storage
   └─> Version control, archival

6. Retention
   └─> Automated retention policies

7. Deletion
   └─> Secure deletion (GDPR compliance)
```

### Retention Policies

```yaml
# config/retention.yaml

retention_policies:
  raw_pcap:
    hot_storage_days: 7
    warm_storage_days: 30
    cold_storage_days: 365
    delete_after_days: 730  # 2 years

  alerts:
    hot_storage_days: 7
    warm_storage_days: 30
    archive_after_days: 90
    delete_after_days: 1095  # 3 years

  training_data:
    retain_forever: true
    compress_after_days: 90

  models:
    retain_production: true
    retain_candidate_days: 90
    retain_archived_days: 365

  logs:
    system_logs_days: 30
    audit_logs_days: 365
    security_logs_days: 2555  # 7 years

  user_data:
    active_users: retain_forever
    deleted_users_days: 30  # GDPR compliance
```

### Automated Cleanup

```python
# scripts/data_cleanup.py

class DataCleanup:
    """Automated data cleanup based on retention policies"""

    def __init__(self, config_path='config/retention.yaml'):
        self.config = load_config(config_path)

    def run_cleanup(self):
        """Run all cleanup tasks"""

        self.cleanup_old_pcap()
        self.cleanup_old_alerts()
        self.cleanup_old_models()
        self.cleanup_old_logs()

    def cleanup_old_pcap(self):
        """Delete old PCAP files"""

        retention_days = self.config['retention_policies']['raw_pcap']['delete_after_days']
        cutoff_date = datetime.now() - timedelta(days=retention_days)

        # Find old files
        pcap_dir = '/data/raw/pcap'
        for filename in os.listdir(pcap_dir):
            filepath = os.path.join(pcap_dir, filename)
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))

            if file_time < cutoff_date:
                os.remove(filepath)
                log.info(f"Deleted old PCAP file: {filename}")

    def cleanup_old_alerts(self):
        """Archive old alerts"""

        retention_days = self.config['retention_policies']['alerts']['archive_after_days']
        cutoff_date = datetime.now() - timedelta(days=retention_days)

        # Move to archive
        old_alerts = db.alerts.find({
            'timestamp': {'$lt': cutoff_date}
        })

        for alert in old_alerts:
            # Move to archive collection
            db.alerts_archive.insert_one(alert)
            db.alerts.delete_one({'_id': alert['_id']})

        log.info(f"Archived {old_alerts.count()} old alerts")
```

## Privacy and Compliance

### PII Handling

```python
# utils/privacy.py

class PrivacyManager:
    """Manage PII and privacy compliance"""

    def anonymize_ip(self, ip_address):
        """Anonymize IP by masking last octet"""
        parts = ip_address.split('.')
        parts[-1] = 'X'
        return '.'.join(parts)

    def hash_sensitive_field(self, value, salt='dids_salt'):
        """Hash sensitive fields"""
        import hashlib
        hashed = hashlib.sha256(f"{value}{salt}".encode()).hexdigest()
        return hashed

    def redact_payload(self, packet):
        """Remove packet payload (keep only headers)"""
        return {
            'timestamp': packet['timestamp'],
            'src_ip': self.anonymize_ip(packet['src_ip']),
            'dst_ip': self.anonymize_ip(packet['dst_ip']),
            'protocol': packet['protocol'],
            'length': packet['length'],
            # Payload REMOVED
        }
```

### GDPR Compliance

```python
# User data deletion (right to be forgotten)
@app.route('/api/users/<user_id>/delete', methods=['DELETE'])
@admin_required
def delete_user_data(user_id):
    """Delete all user data (GDPR compliance)"""

    # Delete user account
    db.users.delete_one({'_id': ObjectId(user_id)})

    # Delete user's alerts
    db.alerts.delete_many({'user_id': user_id})

    # Delete audit logs (keep anonymized)
    db.system_logs.update_many(
        {'user_id': user_id},
        {'$set': {'user_id': 'DELETED', 'email': 'DELETED'}}
    )

    log.info(f"Deleted all data for user {user_id} (GDPR)")

    return jsonify({'success': True})
```

## Backup and Recovery

### Backup Strategy

```yaml
# config/backup.yaml

backup:
  schedule:
    daily:
      - mongodb_alerts
      - mongodb_users
      - redis_cache
    weekly:
      - training_datasets
      - models
    monthly:
      - full_system_backup

  destinations:
    primary: azure_blob_backup
    secondary: aws_s3_backup

  retention:
    daily_backups: 7
    weekly_backups: 4
    monthly_backups: 12

  encryption:
    enabled: true
    algorithm: AES-256
```

### Disaster Recovery

```python
# scripts/disaster_recovery.py

def restore_from_backup(backup_date):
    """Restore system from backup"""

    backup_path = f"/backups/{backup_date}"

    # 1. Restore MongoDB
    subprocess.run([
        'mongorestore',
        '--host', 'mongodb://localhost:27017',
        '--db', 'dids',
        f'{backup_path}/mongodb/'
    ])

    # 2. Restore models
    for model_file in os.listdir(f'{backup_path}/models/'):
        shutil.copy(
            f'{backup_path}/models/{model_file}',
            '/mnt/models/'
        )

    # 3. Restore configurations
    shutil.copytree(
        f'{backup_path}/config/',
        '/etc/dids/config/',
        dirs_exist_ok=True
    )

    log.info(f"Restored system from backup: {backup_date}")
```

## Best Practices

1. **Version Everything**: Datasets, models, preprocessing artifacts
2. **Automate Quality Checks**: Never train on bad data
3. **Document Metadata**: Always include version, timestamp, checksums
4. **Implement Retention**: Automatically clean up old data
5. **Encrypt Sensitive Data**: PII, passwords, payloads
6. **Regular Backups**: Daily MongoDB, weekly models
7. **Test Restores**: Verify backups work before disaster
8. **Monitor Storage**: Set up alerts for disk usage
9. **Audit Data Access**: Log all data access for compliance
10. **Use Compression**: Parquet, Snappy for efficient storage

---

**Last Updated**: 2025-01-20
**Next Review**: 2025-04-20
**Maintained By**: DIDS Data Engineering Team
