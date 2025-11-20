# AI/ML Training Pipeline for IDS

This directory contains the complete machine learning training pipeline for the Distributed Intrusion Detection System (DIDS).

## 📁 Directory Structure

```
ml-training/
├── configs/
│   └── training_config.yaml      # Training configuration
├── data/
│   ├── raw/                       # Raw dataset files (CICIDS2017, NSL-KDD, etc.)
│   ├── processed/                 # Cleaned and processed data
│   └── preprocessed/              # Ready-to-train data with splits
├── models/                        # Saved trained models
├── scripts/
│   ├── data_preprocessing.py     # Data preprocessing pipeline
│   └── train_model.py            # Model training script
├── notebooks/                     # Jupyter notebooks for analysis
└── logs/                          # Training logs and TensorBoard data
```

## 🚀 Quick Start

### 1. Prepare Dataset

Download one of the supported datasets:

#### CICIDS2017 (Recommended)
```bash
# Download from: https://www.unb.ca/cic/datasets/ids-2017.html
# Place CSV files in ml-training/data/raw/
```

#### NSL-KDD
```bash
# Download from: https://www.unb.ca/cic/datasets/nsl.html
# Place KDDTrain+.txt and KDDTest+.txt in ml-training/data/raw/
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

Required packages:
- tensorflow
- scikit-learn
- pandas
- numpy
- matplotlib
- seaborn
- pyyaml
- imbalanced-learn (optional, for SMOTE sampling)

### 3. Preprocess Data

```bash
cd ml-training
python scripts/data_preprocessing.py
```

This will:
- Load and clean the dataset
- Handle missing values and outliers
- Normalize attack labels
- Encode categorical features
- Balance classes using SMOTE (optional)
- Split data into train/val/test sets
- Save preprocessed data and artifacts

### 4. Train Model

```bash
python scripts/train_model.py
```

This will:
- Load preprocessed data
- Build deep neural network
- Train with early stopping and checkpointing
- Generate evaluation metrics
- Save trained model to `dids-dashboard/model/`

## ⚙️ Configuration

Edit `configs/training_config.yaml` to customize:

### Data Configuration
```yaml
data:
  dataset_name: "CICIDS2017"        # Dataset type
  train_ratio: 0.7                   # Train split
  val_ratio: 0.15                    # Validation split
  test_ratio: 0.15                   # Test split
  use_sampling: true                 # Enable SMOTE
  sampling_strategy: "SMOTE"         # Balancing method
```

### Model Architecture
```yaml
model:
  architecture: "deep_neural_network"
  layers:
    - units: 128
      activation: "relu"
      dropout: 0.3
    - units: 64
      activation: "relu"
      dropout: 0.3
  optimizer: "adam"
  learning_rate: 0.001
```

### Training Parameters
```yaml
training:
  epochs: 50
  batch_size: 256
  early_stopping:
    enabled: true
    patience: 10
  use_class_weights: true
```

## 📊 Supported Datasets

### CICIDS2017
- **Size**: ~2.8M samples
- **Features**: 78 network flow features
- **Classes**: 15 attack types + benign
- **Attacks**: DDoS, DoS, PortScan, Botnet, Web attacks, Infiltration, etc.

### CICIDS2018
- **Size**: ~16M samples
- **Features**: 79 network flow features
- **Classes**: 14 attack types + benign

### NSL-KDD
- **Size**: ~148K samples
- **Features**: 41 features
- **Classes**: 4 attack categories + normal
- **Attacks**: DoS, Probe, R2L, U2R

### Custom Dataset
Place CSV files in `data/raw/` with:
- Features as columns
- Label/attack type in last column or column named 'Label'

## 🎯 Attack Types Detected

The trained model can detect:

1. **DDoS** - Distributed Denial of Service
2. **DoS** - Denial of Service (Hulk, GoldenEye, Slowloris, Slowhttptest)
3. **PortScan** - Port scanning attacks
4. **Botnet** - Bot/botnet traffic
5. **Brute Force** - FTP/SSH brute force attacks
6. **Web Attacks** - SQL injection, XSS, web exploits
7. **Infiltration** - Network infiltration attempts
8. **Exploit** - Heartbleed and other exploits

## 📈 Model Performance

Expected performance on CICIDS2017:
- **Accuracy**: 98-99%
- **Precision**: 96-98%
- **Recall**: 95-97%
- **F1-Score**: 96-98%

Performance varies by attack type. Check `dids_metrics.json` after training.

## 🔍 Monitoring Training

### TensorBoard
```bash
tensorboard --logdir ml-training/logs
```

Access at http://localhost:6006

### Training Logs
```bash
tail -f ml-training/training.log
```

## 📦 Output Artifacts

After training, the following files are created:

### In `models/` directory:
- `dids_model_final.keras` - Trained model
- `dids_model_training_history.png` - Training curves
- `dids_model_confusion_matrix.png` - Confusion matrix

### In `dids-dashboard/model/` (deployment):
- `dids_final.keras` - Deployed model
- `scaler.pkl` - Feature scaler
- `label_encoder.pkl` - Label encoder
- `feature_names.json` - Feature names
- `dids_config.json` - Model configuration
- `dids_metrics.json` - Performance metrics
- `dids_classification_report.txt` - Classification report

### In `data/preprocessed/`:
- `X_train.npy`, `y_train.npy` - Training data
- `X_val.npy`, `y_val.npy` - Validation data
- `X_test.npy`, `y_test.npy` - Test data
- `metadata.json` - Dataset metadata

## 🔧 Advanced Usage

### Custom Model Architecture

Edit `configs/training_config.yaml`:
```yaml
model:
  layers:
    - units: 256
      activation: "relu"
      dropout: 0.3
    - units: 128
      activation: "relu"
      dropout: 0.2
    # Add more layers
```

### Hyperparameter Tuning

Adjust learning rate, batch size, epochs:
```yaml
training:
  epochs: 100
  batch_size: 128
  lr_scheduler:
    enabled: true
    factor: 0.5
    patience: 5
```

### Feature Selection

Enable feature selection to reduce dimensions:
```yaml
data:
  use_feature_selection: true
  feature_selection_method: "variance"
  n_features: 50
```

## 🐛 Troubleshooting

### Out of Memory Error
- Reduce batch size: `batch_size: 128` or `64`
- Enable mixed precision: `mixed_precision: true`
- Use smaller dataset sample

### Low Accuracy
- Increase epochs: `epochs: 100`
- Enable class balancing: `use_class_weights: true`
- Use SMOTE: `use_sampling: true`
- Check data quality

### Training Too Slow
- Increase batch size: `batch_size: 512`
- Use GPU: `use_gpu: true`
- Reduce model complexity
- Use fewer features

## 📚 References

- CICIDS2017 Dataset: https://www.unb.ca/cic/datasets/ids-2017.html
- NSL-KDD Dataset: https://www.unb.ca/cic/datasets/nsl.html
- Paper: "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"

## 🤝 Contributing

To add new datasets:
1. Create loader method in `data_preprocessing.py`
2. Add dataset config in `training_config.yaml`
3. Update README with dataset details

## 📄 License

Part of the DIDS project. See main README for license information.
