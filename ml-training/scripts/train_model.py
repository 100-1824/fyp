#!/usr/bin/env python3
"""
Model Training Script for IDS
Trains deep neural network for network intrusion detection
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, callbacks
from sklearn.utils import class_weight
import yaml
import json
import pickle
import logging
from pathlib import Path
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_curve, auc, roc_auc_score
)
import shutil

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class IDSModelTrainer:
    """Train IDS detection model"""

    def __init__(self, config_path: str = "ml-training/configs/training_config.yaml"):
        """Initialize trainer with configuration"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)

        self.preprocessed_path = Path(self.config['data']['preprocessed_data_path'])
        self.model_output_path = Path(self.config['output']['save_path'])
        self.deployment_path = Path(self.config['output']['deployment_path'])

        self.model_output_path.mkdir(parents=True, exist_ok=True)
        self.deployment_path.mkdir(parents=True, exist_ok=True)

        # Load metadata
        with open(self.preprocessed_path / "metadata.json", 'r') as f:
            self.metadata = json.load(f)

        self.n_features = self.metadata['n_features']
        self.n_classes = self.metadata['n_classes']
        self.class_names = self.metadata['class_names']

        # Set random seeds for reproducibility
        np.random.seed(self.config['advanced']['random_seed'])
        tf.random.set_seed(self.config['advanced']['random_seed'])

        logger.info("Initialized model trainer")
        logger.info(f"Features: {self.n_features}, Classes: {self.n_classes}")

    def load_data(self):
        """Load preprocessed data"""
        logger.info("Loading preprocessed data...")

        self.X_train = np.load(self.preprocessed_path / "X_train.npy")
        self.X_val = np.load(self.preprocessed_path / "X_val.npy")
        self.X_test = np.load(self.preprocessed_path / "X_test.npy")
        self.y_train = np.load(self.preprocessed_path / "y_train.npy")
        self.y_val = np.load(self.preprocessed_path / "y_val.npy")
        self.y_test = np.load(self.preprocessed_path / "y_test.npy")

        logger.info(f"Train: {self.X_train.shape}, Val: {self.X_val.shape}, Test: {self.X_test.shape}")

    def build_model(self) -> keras.Model:
        """Build neural network model"""
        logger.info("Building model...")

        model = models.Sequential(name="DIDS_Model")

        # Input layer
        model.add(layers.InputLayer(input_shape=(self.n_features,)))

        # Hidden layers from configuration
        for i, layer_config in enumerate(self.config['model']['layers']):
            model.add(layers.Dense(
                units=layer_config['units'],
                activation=layer_config['activation'],
                name=f'dense_{i+1}'
            ))

            # Add dropout if specified
            if 'dropout' in layer_config and layer_config['dropout'] > 0:
                model.add(layers.Dropout(layer_config['dropout'], name=f'dropout_{i+1}'))

        # Output layer
        model.add(layers.Dense(
            self.n_classes,
            activation=self.config['model']['output_activation'],
            name='output'
        ))

        # Compile model
        optimizer_config = self.config['model']['optimizer']
        learning_rate = self.config['model']['learning_rate']

        if optimizer_config == 'adam':
            optimizer = keras.optimizers.Adam(learning_rate=learning_rate)
        elif optimizer_config == 'sgd':
            optimizer = keras.optimizers.SGD(learning_rate=learning_rate)
        else:
            optimizer = optimizer_config

        model.compile(
            optimizer=optimizer,
            loss=self.config['model']['loss'],
            metrics=['accuracy']
        )

        logger.info("\nModel architecture:")
        model.summary(print_fn=logger.info)

        return model

    def get_callbacks(self) -> list:
        """Configure training callbacks"""
        callback_list = []

        # Early stopping
        if self.config['training']['early_stopping']['enabled']:
            early_stop = callbacks.EarlyStopping(
                monitor=self.config['training']['early_stopping']['monitor'],
                patience=self.config['training']['early_stopping']['patience'],
                restore_best_weights=self.config['training']['early_stopping']['restore_best_weights'],
                verbose=1
            )
            callback_list.append(early_stop)
            logger.info("✓ Early stopping enabled")

        # Learning rate scheduler
        if self.config['training']['lr_scheduler']['enabled']:
            lr_scheduler = callbacks.ReduceLROnPlateau(
                monitor='val_loss',
                factor=self.config['training']['lr_scheduler']['factor'],
                patience=self.config['training']['lr_scheduler']['patience'],
                min_lr=self.config['training']['lr_scheduler']['min_lr'],
                verbose=1
            )
            callback_list.append(lr_scheduler)
            logger.info("✓ Learning rate scheduler enabled")

        # Model checkpoint
        if self.config['training']['checkpoint']['enabled']:
            checkpoint_path = self.model_output_path / "checkpoints" / "model_checkpoint.keras"
            checkpoint_path.parent.mkdir(parents=True, exist_ok=True)

            checkpoint = callbacks.ModelCheckpoint(
                str(checkpoint_path),
                monitor=self.config['training']['checkpoint']['monitor'],
                save_best_only=self.config['training']['checkpoint']['save_best_only'],
                verbose=1
            )
            callback_list.append(checkpoint)
            logger.info("✓ Model checkpoint enabled")

        # TensorBoard
        if self.config['logging']['tensorboard']['enabled']:
            log_dir = Path(self.config['logging']['tensorboard']['log_dir'])
            log_dir = log_dir / datetime.now().strftime("%Y%m%d-%H%M%S")
            log_dir.mkdir(parents=True, exist_ok=True)

            tensorboard = callbacks.TensorBoard(
                log_dir=str(log_dir),
                histogram_freq=1,
                write_graph=True
            )
            callback_list.append(tensorboard)
            logger.info(f"✓ TensorBoard logging to {log_dir}")

        return callback_list

    def calculate_class_weights(self) -> dict:
        """Calculate class weights for imbalanced data"""
        if not self.config['training']['use_class_weights']:
            return None

        logger.info("Calculating class weights...")

        class_weights = class_weight.compute_class_weight(
            'balanced',
            classes=np.unique(self.y_train),
            y=self.y_train
        )

        class_weight_dict = dict(enumerate(class_weights))

        logger.info("Class weights:")
        for i, (class_name, weight) in enumerate(zip(self.class_names, class_weights)):
            logger.info(f"  {class_name}: {weight:.4f}")

        return class_weight_dict

    def train(self):
        """Train the model"""
        logger.info("="*70)
        logger.info("Starting Model Training")
        logger.info("="*70)

        # Load data
        self.load_data()

        # Build model
        self.model = self.build_model()

        # Get callbacks
        callback_list = self.get_callbacks()

        # Calculate class weights
        class_weights = self.calculate_class_weights()

        # Train model
        logger.info("\nStarting training...")
        start_time = datetime.now()

        self.history = self.model.fit(
            self.X_train, self.y_train,
            validation_data=(self.X_val, self.y_val),
            epochs=self.config['training']['epochs'],
            batch_size=self.config['training']['batch_size'],
            class_weight=class_weights,
            callbacks=callback_list,
            verbose=1
        )

        training_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"\nTraining completed in {training_time:.2f} seconds")

        return self.history

    def evaluate(self):
        """Evaluate model on test set"""
        logger.info("="*70)
        logger.info("Evaluating Model")
        logger.info("="*70)

        # Evaluate on test set
        test_loss, test_accuracy = self.model.evaluate(self.X_test, self.y_test, verbose=0)
        logger.info(f"Test Loss: {test_loss:.4f}")
        logger.info(f"Test Accuracy: {test_accuracy:.4f}")

        # Make predictions
        y_pred_proba = self.model.predict(self.X_test, verbose=0)
        y_pred = np.argmax(y_pred_proba, axis=1)

        # Classification report
        report = classification_report(
            self.y_test, y_pred,
            target_names=self.class_names,
            output_dict=True
        )

        logger.info("\nClassification Report:")
        report_str = classification_report(
            self.y_test, y_pred,
            target_names=self.class_names
        )
        logger.info(f"\n{report_str}")

        # Confusion matrix
        cm = confusion_matrix(self.y_test, y_pred)

        # Calculate metrics
        metrics = {
            'test_loss': float(test_loss),
            'test_accuracy': float(test_accuracy),
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'per_class_metrics': {}
        }

        for i, class_name in enumerate(self.class_names):
            if class_name in report:
                metrics['per_class_metrics'][class_name] = report[class_name]

        return metrics, y_pred, y_pred_proba

    def plot_training_history(self):
        """Plot training history"""
        logger.info("Generating training history plots...")

        fig, axes = plt.subplots(1, 2, figsize=(15, 5))

        # Accuracy plot
        axes[0].plot(self.history.history['accuracy'], label='Train Accuracy', linewidth=2)
        axes[0].plot(self.history.history['val_accuracy'], label='Val Accuracy', linewidth=2)
        axes[0].set_title('Model Accuracy', fontsize=14, fontweight='bold')
        axes[0].set_xlabel('Epoch', fontsize=12)
        axes[0].set_ylabel('Accuracy', fontsize=12)
        axes[0].legend(fontsize=10)
        axes[0].grid(True, alpha=0.3)

        # Loss plot
        axes[1].plot(self.history.history['loss'], label='Train Loss', linewidth=2)
        axes[1].plot(self.history.history['val_loss'], label='Val Loss', linewidth=2)
        axes[1].set_title('Model Loss', fontsize=14, fontweight='bold')
        axes[1].set_xlabel('Epoch', fontsize=12)
        axes[1].set_ylabel('Loss', fontsize=12)
        axes[1].legend(fontsize=10)
        axes[1].grid(True, alpha=0.3)

        plt.tight_layout()
        output_path = self.model_output_path / f"{self.config['output']['model_name']}_training_history.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"✓ Saved training history to {output_path}")
        plt.close()

    def plot_confusion_matrix(self, cm: np.ndarray):
        """Plot confusion matrix"""
        logger.info("Generating confusion matrix plot...")

        plt.figure(figsize=(12, 10))
        sns.heatmap(
            cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=self.class_names,
            yticklabels=self.class_names,
            cbar_kws={'label': 'Count'}
        )
        plt.title('Confusion Matrix', fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Predicted Label', fontsize=12)
        plt.ylabel('True Label', fontsize=12)
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()

        output_path = self.model_output_path / f"{self.config['output']['model_name']}_confusion_matrix.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        logger.info(f"✓ Saved confusion matrix to {output_path}")
        plt.close()

    def save_model(self, metrics: dict):
        """Save trained model and artifacts"""
        logger.info("Saving model and artifacts...")

        model_name = self.config['output']['model_name']

        # Save model
        model_path = self.model_output_path / f"{model_name}_final.keras"
        self.model.save(str(model_path))
        logger.info(f"✓ Saved model to {model_path}")

        # Save to deployment directory
        deployment_model_path = self.deployment_path / f"{model_name}_final.keras"
        shutil.copy(model_path, deployment_model_path)
        logger.info(f"✓ Copied model to deployment: {deployment_model_path}")

        # Save scaler
        if self.config['output']['save_scaler']:
            scaler_src = self.preprocessed_path / "scaler.pkl"
            scaler_dst = self.deployment_path / "scaler.pkl"
            shutil.copy(scaler_src, scaler_dst)
            logger.info(f"✓ Copied scaler to deployment")

        # Save label encoder
        if self.config['output']['save_label_encoder']:
            encoder_src = self.preprocessed_path / "label_encoder.pkl"
            encoder_dst = self.deployment_path / "label_encoder.pkl"
            shutil.copy(encoder_src, encoder_dst)
            logger.info(f"✓ Copied label encoder to deployment")

        # Save feature names
        if self.config['output']['save_feature_names']:
            features_src = self.preprocessed_path / "feature_names.json"
            features_dst = self.deployment_path / "feature_names.json"
            shutil.copy(features_src, features_dst)
            logger.info(f"✓ Copied feature names to deployment")

        # Save metrics
        if self.config['output']['save_metrics']:
            metrics_path = self.deployment_path / f"{model_name}_metrics.json"
            with open(metrics_path, 'w') as f:
                json.dump(metrics, f, indent=2)
            logger.info(f"✓ Saved metrics to {metrics_path}")

        # Save config
        if self.config['output']['save_config']:
            config_data = {
                'model_name': model_name,
                'n_features': self.n_features,
                'n_classes': self.n_classes,
                'class_names': self.class_names,
                'training_date': datetime.now().isoformat(),
                'architecture': self.config['model']
            }
            config_path = self.deployment_path / f"{model_name}_config.json"
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            logger.info(f"✓ Saved config to {config_path}")

        # Save classification report as text
        report_path = self.deployment_path / f"{model_name}_classification_report.txt"
        report_str = classification_report(
            self.y_test,
            np.argmax(self.model.predict(self.X_test, verbose=0), axis=1),
            target_names=self.class_names
        )
        with open(report_path, 'w') as f:
            f.write("="*70 + "\n")
            f.write("CLASSIFICATION REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(report_str)
        logger.info(f"✓ Saved classification report to {report_path}")

    def run_training_pipeline(self):
        """Execute complete training pipeline"""
        logger.info("\n" + "="*70)
        logger.info("IDS MODEL TRAINING PIPELINE")
        logger.info("="*70 + "\n")

        # Train model
        self.train()

        # Evaluate model
        metrics, y_pred, y_pred_proba = self.evaluate()

        # Generate visualizations
        if self.config['output']['save_visualizations']:
            self.plot_training_history()
            self.plot_confusion_matrix(np.array(metrics['confusion_matrix']))

        # Save model and artifacts
        self.save_model(metrics)

        logger.info("\n" + "="*70)
        logger.info("TRAINING PIPELINE COMPLETED SUCCESSFULLY!")
        logger.info("="*70)

        # Print summary
        print("\n" + "="*70)
        print("TRAINING SUMMARY")
        print("="*70)
        print(f"Model: {self.config['output']['model_name']}")
        print(f"Test Accuracy: {metrics['test_accuracy']:.4f}")
        print(f"Test Loss: {metrics['test_loss']:.4f}")
        print(f"\nModel saved to: {self.deployment_path}")
        print("="*70 + "\n")

        return metrics


if __name__ == "__main__":
    trainer = IDSModelTrainer()
    metrics = trainer.run_training_pipeline()
