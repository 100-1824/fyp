#!/usr/bin/env python3
"""
Test Script for Trained Double DQN Models
Evaluates model performance on test data
"""

import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import tensorflow as tf
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score)
from tensorflow import keras

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))


class DQNModelTester:
    """Test trained DQN models"""

    def __init__(self, model_path, test_data_path=None):
        """
        Initialize tester

        Args:
            model_path: Path to trained .keras model
            test_data_path: Path to test data directory (optional)
        """
        self.model_path = Path(model_path)
        self.test_data_path = (
            Path(test_data_path) if test_data_path else Path(__file__).parent.parent
        )
        self.model = None
        self.X_test = None
        self.y_test = None

    def load_model(self):
        """Load trained model"""
        print(f"Loading model from: {self.model_path}")
        try:
            self.model = keras.models.load_model(str(self.model_path))
            print(f"✓ Model loaded successfully")
            print(f"  Input shape: {self.model.input_shape}")
            print(f"  Output shape: {self.model.output_shape}")
            return True
        except Exception as e:
            print(f"✗ Error loading model: {e}")
            return False

    def load_test_data(self):
        """Load test data"""
        # Try multiple locations for test data
        possible_paths = [
            self.test_data_path / "X_test.npy",
            self.test_data_path / "training_data" / "X_test.npy",
            Path(__file__).parent.parent / "X_test.npy",
        ]

        for path in possible_paths:
            if path.exists():
                print(f"Loading test data from: {path.parent}")
                self.X_test = np.load(path)
                self.y_test = np.load(path.parent / "y_test.npy")
                print(f"✓ Loaded {len(self.X_test)} test samples")
                print(f"  Features: {self.X_test.shape[1]}")
                print(
                    f"  Benign: {np.sum(self.y_test == 0)}, Attacks: {np.sum(self.y_test == 1)}"
                )
                return True

        print("✗ Test data not found. Please specify correct path.")
        return False

    def predict(self, X):
        """Get model predictions"""
        q_values = self.model.predict(X, verbose=0)
        actions = np.argmax(q_values, axis=1)

        # Map actions to predictions
        # Action 0: Allow (benign), Action 1: Block (attack), Action 2: Quarantine (attack)
        predictions = np.where(actions == 0, 0, 1)
        return predictions, actions, q_values

    def evaluate(self):
        """Evaluate model on test data"""
        print("\n" + "=" * 70)
        print("EVALUATING MODEL")
        print("=" * 70)

        predictions, actions, q_values = self.predict(self.X_test)

        # Calculate metrics
        accuracy = accuracy_score(self.y_test, predictions)
        f1 = f1_score(self.y_test, predictions, average="weighted")

        print(f"\n📊 Overall Performance:")
        print(f"  Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"  F1 Score: {f1:.4f}")

        # Classification report
        print(f"\n📋 Detailed Classification Report:")
        print(
            classification_report(
                self.y_test, predictions, target_names=["Benign", "Attack"]
            )
        )

        # Confusion matrix
        cm = confusion_matrix(self.y_test, predictions)
        print(f"\n🔢 Confusion Matrix:")
        print(f"                Predicted")
        print(f"              Benign  Attack")
        print(f"Actual Benign  {cm[0,0]:6d}  {cm[0,1]:6d}")
        print(f"       Attack  {cm[1,0]:6d}  {cm[1,1]:6d}")

        # Action distribution
        print(f"\n🎯 Action Distribution:")
        action_names = ["Allow", "Block", "Quarantine"]
        for i, name in enumerate(action_names):
            count = np.sum(actions == i)
            pct = count / len(actions) * 100
            print(f"  {name:12s}: {count:6d} ({pct:5.2f}%)")

        # Q-value statistics
        print(f"\n📈 Q-Value Statistics:")
        print(f"  Mean Q-values: {np.mean(q_values, axis=0)}")
        print(f"  Max Q-values:  {np.max(q_values, axis=0)}")
        print(f"  Min Q-values:  {np.min(q_values, axis=0)}")

        return {
            "accuracy": accuracy,
            "f1_score": f1,
            "predictions": predictions,
            "actions": actions,
            "q_values": q_values,
            "confusion_matrix": cm,
        }

    def plot_confusion_matrix(self, cm, save_path=None):
        """Plot confusion matrix"""
        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=["Benign", "Attack"],
            yticklabels=["Benign", "Attack"],
        )
        plt.ylabel("Actual")
        plt.xlabel("Predicted")
        plt.title("Double DQN Model - Confusion Matrix")

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"✓ Confusion matrix saved to: {save_path}")
        plt.show()

    def test_sample_predictions(self, num_samples=10):
        """Show predictions for random samples"""
        print("\n" + "=" * 70)
        print(f"SAMPLE PREDICTIONS ({num_samples} random samples)")
        print("=" * 70)

        indices = np.random.choice(len(self.X_test), num_samples, replace=False)

        for idx in indices:
            sample = self.X_test[idx : idx + 1]
            true_label = self.y_test[idx]

            pred, action, q_vals = self.predict(sample)

            true_name = "Benign" if true_label == 0 else "Attack"
            pred_name = "Benign" if pred[0] == 0 else "Attack"
            action_names = ["Allow", "Block", "Quarantine"]

            match = "✓" if pred[0] == true_label else "✗"

            print(f"\nSample {idx}:")
            print(
                f"  True: {true_name:7s} | Predicted: {pred_name:7s} | Action: {action_names[action[0]]:10s} {match}"
            )
            print(
                f"  Q-values: Allow={q_vals[0][0]:.3f}, Block={q_vals[0][1]:.3f}, Quarantine={q_vals[0][2]:.3f}"
            )


def main():
    """Main testing function"""
    import argparse

    parser = argparse.ArgumentParser(description="Test trained DQN model")
    parser.add_argument(
        "--model",
        type=str,
        default="dids-dashboard/model/double_dqn_final.keras",
        help="Path to trained model",
    )
    parser.add_argument(
        "--data", type=str, default=None, help="Path to test data directory"
    )
    parser.add_argument(
        "--samples", type=int, default=10, help="Number of sample predictions to show"
    )
    parser.add_argument(
        "--plot", action="store_true", help="Show confusion matrix plot"
    )

    args = parser.parse_args()

    print("=" * 70)
    print("DOUBLE DQN MODEL TESTING")
    print("=" * 70)

    # Initialize tester
    tester = DQNModelTester(args.model, args.data)

    # Load model
    if not tester.load_model():
        return

    # Load test data
    if not tester.load_test_data():
        print("\n⚠️  Cannot proceed without test data.")
        print(
            "Please provide test data using --data argument or place X_test.npy and y_test.npy in project root"
        )
        return

    # Evaluate model
    results = tester.evaluate()

    # Show sample predictions
    tester.test_sample_predictions(args.samples)

    # Plot confusion matrix
    if args.plot:
        tester.plot_confusion_matrix(results["confusion_matrix"])

    print("\n" + "=" * 70)
    print("TESTING COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
