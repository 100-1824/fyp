#!/usr/bin/env python3
"""
Generate synthetic training data for RL agent
Creates realistic network flow features for training
"""

import logging
from pathlib import Path

import numpy as np

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def generate_synthetic_data(
    n_samples: int = 50000,
    n_features: int = 77,
    attack_ratio: float = 0.3,
    output_dir: str = "ml-training/data/preprocessed",
):
    """
    Generate synthetic network flow data

    Args:
        n_samples: Number of samples to generate
        n_features: Number of features (77 for CICIDS2017)
        attack_ratio: Ratio of attack samples
        output_dir: Output directory
    """
    logger.info(f"Generating {n_samples} synthetic samples with {n_features} features")

    # Create output directory
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Calculate numbers
    n_attacks = int(n_samples * attack_ratio)
    n_benign = n_samples - n_attacks

    logger.info(f"Benign samples: {n_benign}, Attack samples: {n_attacks}")

    # Generate benign traffic (lower values, more normal distribution)
    X_benign = np.random.normal(loc=0.2, scale=0.3, size=(n_benign, n_features))
    y_benign = np.zeros(n_benign)

    # Generate attack traffic (higher values, more varied)
    X_attacks = np.random.normal(loc=0.7, scale=0.4, size=(n_attacks, n_features))
    # Add some extreme values for attacks
    X_attacks += np.random.exponential(scale=0.3, size=(n_attacks, n_features))
    y_attacks = np.ones(n_attacks)

    # Combine and shuffle
    X_all = np.vstack([X_benign, X_attacks])
    y_all = np.hstack([y_benign, y_attacks])

    # Shuffle
    indices = np.arange(n_samples)
    np.random.shuffle(indices)
    X_all = X_all[indices]
    y_all = y_all[indices]

    # Normalize features to [-1, 1] range
    X_all = np.clip(X_all, -2, 2)

    # Split into train/test (80/20)
    split_idx = int(n_samples * 0.8)

    X_train = X_all[:split_idx].astype(np.float32)
    X_test = X_all[split_idx:].astype(np.float32)
    y_train = y_all[:split_idx].astype(np.int32)
    y_test = y_all[split_idx:].astype(np.int32)

    # Save
    logger.info(f"Saving to {output_path}")
    np.save(output_path / "X_train.npy", X_train)
    np.save(output_path / "X_test.npy", X_test)
    np.save(output_path / "y_train.npy", y_train)
    np.save(output_path / "y_test.npy", y_test)

    logger.info("=" * 60)
    logger.info("Generated Synthetic Data:")
    logger.info(f"  X_train: {X_train.shape}, y_train: {y_train.shape}")
    logger.info(f"  X_test: {X_test.shape}, y_test: {y_test.shape}")
    logger.info(f"  Train attacks: {np.sum(y_train)}")
    logger.info(f"  Test attacks: {np.sum(y_test)}")
    logger.info("=" * 60)

    return X_train, X_test, y_train, y_test


if __name__ == "__main__":
    generate_synthetic_data(n_samples=50000)
