# AI Detection Model Setup

## Overview
The AI Detection service uses a trained neural network model to detect network intrusions in real-time.

## Required Files

The following files must be present in the `model/` directory:

### Core Model Files (Tracked in Git)
- `dids_final.keras` or `dids.keras` - Trained Keras model
- `feature_names.json` - List of feature names used by the model
- `dids_config.json` - Model configuration including class names
- `dids_metrics.json` - Model performance metrics

### Generated Files (Not in Git)
- `label_encoder.pkl` - Label encoder for attack type classification

## Setup Instructions

### 1. Generate Label Encoder

If the `label_encoder.pkl` file is missing, you can generate it using the following Python code:

```python
import json
import pickle
from sklearn.preprocessing import LabelEncoder
from pathlib import Path

# Load config
config_path = Path('model/dids_config.json')
with open(config_path, 'r') as f:
    config = json.load(f)

# Create label encoder
le = LabelEncoder()
le.fit(config['class_names'])

# Save to file
output_path = Path('model/label_encoder.pkl')
with open(output_path, 'wb') as f:
    pickle.dump(le, f)

print(f"Label encoder saved to {output_path}")
```

Or simply run:
```bash
cd dids-dashboard
python3 -c "
import json, pickle
from sklearn.preprocessing import LabelEncoder
from pathlib import Path
config = json.load(open('model/dids_config.json'))
le = LabelEncoder()
le.fit(config['class_names'])
pickle.dump(le, open('model/label_encoder.pkl', 'wb'))
print('Label encoder created')
"
```

### 2. Optional: Scaler

The scaler is optional. If not present, the service will use default normalization.

## Attack Types Detected

The model can detect the following attack types:
- BENIGN (normal traffic)
- Botnet
- DDoS
- DoS attacks (GoldenEye, Hulk, Slowhttptest, Slowloris)
- FTP-Patator
- Infiltration - Portscan
- Portscan
- SSH-Patator
- Web Attack (Brute Force, XSS)

## Model Performance

Check `dids_metrics.json` for detailed performance metrics including:
- Accuracy
- Precision
- Recall
- F1-score
- Per-class performance

## Troubleshooting

### Model Not Loading
- Ensure all required files are present in the `model/` directory
- Check that TensorFlow is installed: `pip install tensorflow`
- Verify label_encoder.pkl exists (regenerate if needed)

### AI Service Not Ready
Check the application logs for specific error messages. Common issues:
- Missing dependencies (tensorflow, scikit-learn, numpy)
- Incorrect model path
- Missing label encoder

## Dependencies

Required Python packages:
```
tensorflow
scikit-learn
numpy
pandas
```

Install with: `pip install tensorflow scikit-learn numpy pandas`
