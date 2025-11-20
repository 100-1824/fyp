#!/usr/bin/env python3
"""
Data Preprocessing Script for IDS Datasets
Supports: CICIDS2017, CICIDS2018, NSL-KDD, UNSW-NB15, and custom datasets
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import yaml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, StandardScaler

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class DataPreprocessor:
    """Preprocess IDS datasets for training"""

    def __init__(self, config_path: str = "ml-training/configs/training_config.yaml"):
        """Initialize preprocessor with configuration"""
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)

        self.dataset_name = self.config["data"]["dataset_name"]
        self.raw_data_path = Path(self.config["data"]["raw_data_path"])
        self.processed_path = Path(self.config["data"]["processed_data_path"])
        self.preprocessed_path = Path(self.config["data"]["preprocessed_data_path"])

        # Create directories
        self.processed_path.mkdir(parents=True, exist_ok=True)
        self.preprocessed_path.mkdir(parents=True, exist_ok=True)

        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()

        logger.info(f"Initialized preprocessor for {self.dataset_name}")

    def load_cicids2017(self) -> pd.DataFrame:
        """Load CICIDS2017 dataset"""
        logger.info("Loading CICIDS2017 dataset...")

        csv_files = list(self.raw_data_path.glob("*.csv"))
        if not csv_files:
            raise FileNotFoundError(f"No CSV files found in {self.raw_data_path}")

        logger.info(f"Found {len(csv_files)} CSV files")

        dfs = []
        for csv_file in csv_files:
            logger.info(f"Reading {csv_file.name}...")
            try:
                df = pd.read_csv(csv_file, encoding="utf-8", low_memory=False)
                dfs.append(df)
            except Exception as e:
                logger.warning(f"Error reading {csv_file.name}: {e}")
                try:
                    df = pd.read_csv(csv_file, encoding="latin-1", low_memory=False)
                    dfs.append(df)
                except Exception as e2:
                    logger.error(f"Failed to read {csv_file.name}: {e2}")

        if not dfs:
            raise ValueError("No data loaded successfully")

        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Loaded {len(df)} samples with {len(df.columns)} features")

        return df

    def load_nsl_kdd(self) -> pd.DataFrame:
        """Load NSL-KDD dataset"""
        logger.info("Loading NSL-KDD dataset...")

        # NSL-KDD column names
        columns = [
            "duration",
            "protocol_type",
            "service",
            "flag",
            "src_bytes",
            "dst_bytes",
            "land",
            "wrong_fragment",
            "urgent",
            "hot",
            "num_failed_logins",
            "logged_in",
            "num_compromised",
            "root_shell",
            "su_attempted",
            "num_root",
            "num_file_creations",
            "num_shells",
            "num_access_files",
            "num_outbound_cmds",
            "is_host_login",
            "is_guest_login",
            "count",
            "srv_count",
            "serror_rate",
            "srv_serror_rate",
            "rerror_rate",
            "srv_rerror_rate",
            "same_srv_rate",
            "diff_srv_rate",
            "srv_diff_host_rate",
            "dst_host_count",
            "dst_host_srv_count",
            "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate",
            "dst_host_serror_rate",
            "dst_host_srv_serror_rate",
            "dst_host_rerror_rate",
            "dst_host_srv_rerror_rate",
            "label",
            "difficulty",
        ]

        train_file = self.raw_data_path / "KDDTrain+.txt"
        test_file = self.raw_data_path / "KDDTest+.txt"

        dfs = []
        for file in [train_file, test_file]:
            if file.exists():
                df = pd.read_csv(file, names=columns, header=None)
                dfs.append(df)

        if not dfs:
            raise FileNotFoundError("NSL-KDD files not found")

        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Loaded {len(df)} samples")

        return df

    def load_dataset(self) -> pd.DataFrame:
        """Load dataset based on configuration"""
        if self.dataset_name == "CICIDS2017":
            return self.load_cicids2017()
        elif self.dataset_name == "NSL-KDD":
            return self.load_nsl_kdd()
        else:
            # Try loading any CSV files as custom dataset
            logger.info(f"Loading custom dataset from {self.raw_data_path}")
            csv_files = list(self.raw_data_path.glob("*.csv"))
            if csv_files:
                df = pd.read_csv(csv_files[0])
                logger.info(f"Loaded custom dataset with {len(df)} samples")
                return df
            else:
                raise ValueError(f"Unknown dataset: {self.dataset_name}")

    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean and prepare data"""
        logger.info("Cleaning data...")

        original_size = len(df)

        # Identify label column (usually 'Label' or 'label' or last column)
        label_col = None
        for col in ["Label", "label", "attack_type", "class"]:
            if col in df.columns:
                label_col = col
                break

        if label_col is None:
            label_col = df.columns[-1]
            logger.warning(
                f"No standard label column found, using last column: {label_col}"
            )

        # Store label column
        self.label_column = label_col

        # Clean column names
        df.columns = df.columns.str.strip()

        # Remove duplicate rows
        df = df.drop_duplicates()
        logger.info(f"Removed {original_size - len(df)} duplicate rows")

        # Handle missing values
        missing_before = df.isnull().sum().sum()

        # For numeric columns, fill with median
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if col != label_col:
                df[col].fillna(df[col].median(), inplace=True)

        # For categorical columns, fill with mode
        categorical_cols = df.select_dtypes(include=["object"]).columns
        for col in categorical_cols:
            if col != label_col:
                df[col].fillna(
                    df[col].mode()[0] if len(df[col].mode()) > 0 else "unknown",
                    inplace=True,
                )

        missing_after = df.isnull().sum().sum()
        logger.info(f"Handled {missing_before - missing_after} missing values")

        # Remove rows with missing labels
        df = df[df[label_col].notna()]

        # Handle infinite values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        logger.info(f"Data cleaned: {len(df)} samples remaining")

        return df

    def encode_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Encode categorical features"""
        logger.info("Encoding categorical features...")

        categorical_cols = df.select_dtypes(include=["object"]).columns.tolist()

        # Remove label column from categorical encoding
        if self.label_column in categorical_cols:
            categorical_cols.remove(self.label_column)

        for col in categorical_cols:
            logger.info(f"Encoding {col}...")
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))

        return df

    def normalize_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize attack labels to standard categories"""
        logger.info("Normalizing attack labels...")

        # Define label mapping for CICIDS2017
        label_mapping = {
            "BENIGN": "Benign",
            "benign": "Benign",
            "normal": "Benign",
            "Normal": "Benign",
            # DDoS attacks
            "DDoS": "DDoS",
            "ddos": "DDoS",
            # DoS attacks
            "DoS Hulk": "DoS",
            "DoS GoldenEye": "DoS",
            "DoS slowloris": "DoS",
            "DoS Slowhttptest": "DoS",
            "DoS slowhttptest": "DoS",
            # Port Scan
            "PortScan": "PortScan",
            "Portscan": "PortScan",
            # Botnet
            "Bot": "Botnet",
            "bot": "Botnet",
            # FTP attacks
            "FTP-Patator": "Brute Force",
            # SSH attacks
            "SSH-Patator": "Brute Force",
            # Web attacks
            "Web Attack � Brute Force": "Web Attack",
            "Web Attack � XSS": "Web Attack",
            "Web Attack � Sql Injection": "Web Attack",
            "Web Attack - Brute Force": "Web Attack",
            "Web Attack - XSS": "Web Attack",
            "Web Attack - Sql Injection": "Web Attack",
            # Infiltration
            "Infiltration": "Infiltration",
            "Infiltration - Portscan": "Infiltration",
            # Heartbleed
            "Heartbleed": "Exploit",
        }

        df[self.label_column] = df[self.label_column].astype(str).str.strip()
        df[self.label_column] = df[self.label_column].replace(label_mapping)

        # Show label distribution
        label_counts = df[self.label_column].value_counts()
        logger.info(f"\nLabel distribution:\n{label_counts}")

        return df

    def balance_dataset(
        self, X: np.ndarray, y: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Balance dataset using sampling strategy"""
        if not self.config["data"]["use_sampling"]:
            return X, y

        logger.info("Balancing dataset...")

        strategy = self.config["data"]["sampling_strategy"]

        try:
            if strategy == "SMOTE":
                from imblearn.over_sampling import SMOTE

                sampler = SMOTE(random_state=42, k_neighbors=3)
                X_balanced, y_balanced = sampler.fit_resample(X, y)
            elif strategy == "RandomUnderSampler":
                from imblearn.under_sampling import RandomUnderSampler

                sampler = RandomUnderSampler(random_state=42)
                X_balanced, y_balanced = sampler.fit_resample(X, y)
            else:
                # Hybrid approach
                from imblearn.over_sampling import SMOTE
                from imblearn.pipeline import Pipeline
                from imblearn.under_sampling import RandomUnderSampler

                over = SMOTE(random_state=42, k_neighbors=3)
                under = RandomUnderSampler(random_state=42)
                pipeline = Pipeline([("over", over), ("under", under)])
                X_balanced, y_balanced = pipeline.fit_resample(X, y)

            logger.info(f"Balanced from {len(X)} to {len(X_balanced)} samples")
            return X_balanced, y_balanced

        except ImportError:
            logger.warning("imbalanced-learn not installed. Skipping balancing.")
            logger.info("Install with: pip install imbalanced-learn")
            return X, y
        except Exception as e:
            logger.warning(f"Error during balancing: {e}. Using original data.")
            return X, y

    def feature_selection(
        self, X: np.ndarray, feature_names: List[str]
    ) -> Tuple[np.ndarray, List[str]]:
        """Select most important features"""
        if not self.config["data"]["use_feature_selection"]:
            return X, feature_names

        logger.info("Performing feature selection...")

        method = self.config["data"]["feature_selection_method"]
        n_features = min(self.config["data"]["n_features"], X.shape[1])

        if method == "variance":
            from sklearn.feature_selection import VarianceThreshold

            selector = VarianceThreshold(threshold=0.01)
            X_selected = selector.fit_transform(X)
            selected_indices = selector.get_support(indices=True)

        elif method == "correlation":
            # Remove highly correlated features
            df_features = pd.DataFrame(X, columns=feature_names)
            corr_matrix = df_features.corr().abs()
            upper_triangle = corr_matrix.where(
                np.triu(np.ones(corr_matrix.shape), k=1).astype(bool)
            )
            to_drop = [
                col for col in upper_triangle.columns if any(upper_triangle[col] > 0.95)
            ]
            selected_features = [f for f in feature_names if f not in to_drop]
            selected_indices = [
                i for i, f in enumerate(feature_names) if f in selected_features
            ]
            X_selected = X[:, selected_indices]

        else:
            return X, feature_names

        selected_features = [feature_names[i] for i in selected_indices]
        logger.info(
            f"Selected {len(selected_features)} features from {len(feature_names)}"
        )

        return X_selected, selected_features

    def preprocess(self) -> Dict:
        """Main preprocessing pipeline"""
        logger.info("=" * 70)
        logger.info("Starting Data Preprocessing Pipeline")
        logger.info("=" * 70)

        # 1. Load dataset
        df = self.load_dataset()

        # 2. Clean data
        df = self.clean_data(df)

        # 3. Normalize labels
        df = self.normalize_labels(df)

        # 4. Encode categorical features
        df = self.encode_categorical_features(df)

        # 5. Separate features and labels
        X = df.drop(columns=[self.label_column]).values
        y = df[self.label_column].values
        feature_names = df.drop(columns=[self.label_column]).columns.tolist()

        logger.info(f"Features shape: {X.shape}")
        logger.info(f"Labels shape: {y.shape}")

        # 6. Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        class_names = self.label_encoder.classes_.tolist()
        logger.info(f"Classes: {class_names}")

        # 7. Feature selection
        X_selected, selected_features = self.feature_selection(X, feature_names)

        # 8. Scale features
        logger.info("Scaling features...")
        X_scaled = self.scaler.fit_transform(X_selected)

        # 9. Balance dataset
        X_balanced, y_balanced = self.balance_dataset(X_scaled, y_encoded)

        # 10. Split data
        logger.info("Splitting data...")
        train_ratio = self.config["data"]["train_ratio"]
        val_ratio = self.config["data"]["val_ratio"]
        test_ratio = self.config["data"]["test_ratio"]

        # First split: train + val vs test
        X_train_val, X_test, y_train_val, y_test = train_test_split(
            X_balanced,
            y_balanced,
            test_size=test_ratio,
            random_state=42,
            stratify=y_balanced,
        )

        # Second split: train vs val
        val_size = val_ratio / (train_ratio + val_ratio)
        X_train, X_val, y_train, y_val = train_test_split(
            X_train_val,
            y_train_val,
            test_size=val_size,
            random_state=42,
            stratify=y_train_val,
        )

        logger.info(f"Train set: {X_train.shape}")
        logger.info(f"Validation set: {X_val.shape}")
        logger.info(f"Test set: {X_test.shape}")

        # 11. Save preprocessed data
        logger.info("Saving preprocessed data...")

        np.save(self.preprocessed_path / "X_train.npy", X_train)
        np.save(self.preprocessed_path / "X_val.npy", X_val)
        np.save(self.preprocessed_path / "X_test.npy", X_test)
        np.save(self.preprocessed_path / "y_train.npy", y_train)
        np.save(self.preprocessed_path / "y_val.npy", y_val)
        np.save(self.preprocessed_path / "y_test.npy", y_test)

        # Save preprocessors
        with open(self.preprocessed_path / "scaler.pkl", "wb") as f:
            pickle.dump(self.scaler, f)

        with open(self.preprocessed_path / "label_encoder.pkl", "wb") as f:
            pickle.dump(self.label_encoder, f)

        # Save feature names
        with open(self.preprocessed_path / "feature_names.json", "w") as f:
            json.dump(selected_features, f, indent=2)

        # Save metadata
        metadata = {
            "dataset_name": self.dataset_name,
            "n_samples": len(X_balanced),
            "n_features": X_train.shape[1],
            "n_classes": len(class_names),
            "class_names": class_names,
            "feature_names": selected_features,
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
        }

        with open(self.preprocessed_path / "metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

        logger.info("=" * 70)
        logger.info("Preprocessing Complete!")
        logger.info("=" * 70)

        return metadata


if __name__ == "__main__":
    preprocessor = DataPreprocessor()
    metadata = preprocessor.preprocess()

    print("\n" + "=" * 70)
    print("PREPROCESSING SUMMARY")
    print("=" * 70)
    print(f"Dataset: {metadata['dataset_name']}")
    print(f"Total samples: {metadata['n_samples']}")
    print(f"Features: {metadata['n_features']}")
    print(f"Classes: {metadata['n_classes']}")
    print(f"Class names: {', '.join(metadata['class_names'])}")
    print(f"\nTrain: {metadata['train_samples']} samples")
    print(f"Validation: {metadata['val_samples']} samples")
    print(f"Test: {metadata['test_samples']} samples")
    print("=" * 70)
