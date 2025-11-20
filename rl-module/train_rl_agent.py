#!/usr/bin/env python3
"""
Train RL Agent for Adaptive IDS
Uses DQN/Double DQN for learning optimal threat response policies
"""

import numpy as np
import sys
import logging
from pathlib import Path
import json
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import argparse

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from rl_module.environments.ids_environment import IDSEnvironment
from rl_module.agents.dqn_agent import DQNAgent, DoubleDQNAgent

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RLTrainer:
    """Train RL agent for IDS"""

    def __init__(self,
                 agent_type: str = 'double_dqn',
                 n_features: int = 77,
                 n_episodes: int = 1000,
                 max_steps: int = 1000,
                 update_target_freq: int = 10,
                 save_freq: int = 50,
                 output_dir: str = 'rl-module/trained_models'):
        """
        Initialize RL trainer

        Args:
            agent_type: Type of agent ('dqn' or 'double_dqn')
            n_features: Number of input features
            n_episodes: Number of training episodes
            max_steps: Maximum steps per episode
            update_target_freq: Frequency to update target network
            save_freq: Frequency to save model
            output_dir: Directory to save models
        """
        self.agent_type = agent_type
        self.n_features = n_features
        self.n_episodes = n_episodes
        self.max_steps = max_steps
        self.update_target_freq = update_target_freq
        self.save_freq = save_freq
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Create environment
        self.env = IDSEnvironment(n_features=n_features, max_steps=max_steps)

        # Create agent
        if agent_type == 'double_dqn':
            self.agent = DoubleDQNAgent(
                state_size=n_features,
                action_size=3,
                learning_rate=0.001,
                gamma=0.95,
                epsilon=1.0,
                epsilon_min=0.01,
                epsilon_decay=0.995,
                batch_size=64,
                buffer_size=10000
            )
        else:
            self.agent = DQNAgent(
                state_size=n_features,
                action_size=3,
                learning_rate=0.001,
                gamma=0.95,
                epsilon=1.0,
                epsilon_min=0.01,
                epsilon_decay=0.995,
                batch_size=64,
                buffer_size=10000
            )

        # Training metrics
        self.episode_rewards = []
        self.episode_accuracies = []
        self.episode_precisions = []
        self.episode_recalls = []
        self.episode_f1_scores = []
        self.episode_losses = []

        logger.info(f"Initialized {agent_type} trainer")

    def load_training_data(self, data_path: str = 'ml-training/data/preprocessed'):
        """
        Load preprocessed data for training

        Args:
            data_path: Path to preprocessed data directory
        """
        logger.info("Loading training data...")

        data_path = Path(data_path)

        X_train = np.load(data_path / 'X_train.npy')
        y_train = np.load(data_path / 'y_train.npy')

        # Convert to binary: 0 = benign, >0 = attack
        y_train_binary = (y_train > 0).astype(int)

        logger.info(f"Loaded {len(X_train)} training samples")
        logger.info(f"Benign: {np.sum(y_train_binary == 0)}, Attacks: {np.sum(y_train_binary == 1)}")

        # Load data into environment
        self.env.load_data(X_train, y_train_binary)

    def train(self):
        """Main training loop"""
        logger.info("="*70)
        logger.info(f"Starting RL Training - {self.agent_type.upper()}")
        logger.info("="*70)
        logger.info(f"Episodes: {self.n_episodes}")
        logger.info(f"Max steps per episode: {self.max_steps}")
        logger.info("="*70)

        for episode in range(self.n_episodes):
            # Reset environment
            state = self.env.reset()
            episode_reward = 0
            episode_loss = []

            # Run episode
            for step in range(self.max_steps):
                # Agent selects action
                action = self.agent.act(state, training=True)

                # Environment step
                next_state, reward, done, info = self.env.step(action)

                # Store experience
                self.agent.remember(state, action, reward, next_state, done)

                # Train agent
                loss = self.agent.replay()
                if loss is not None:
                    episode_loss.append(loss)

                episode_reward += reward
                state = next_state

                if done:
                    break

            # Update target network periodically
            if episode % self.update_target_freq == 0:
                self.agent.update_target_model()

            # Get episode statistics
            stats = self.env.get_episode_stats()

            # Store metrics
            self.episode_rewards.append(episode_reward)
            self.episode_accuracies.append(stats['accuracy'])
            self.episode_precisions.append(stats['precision'])
            self.episode_recalls.append(stats['recall'])
            self.episode_f1_scores.append(stats['f1_score'])
            self.episode_losses.append(np.mean(episode_loss) if episode_loss else 0)

            # Log progress
            if (episode + 1) % 10 == 0:
                avg_reward = np.mean(self.episode_rewards[-10:])
                avg_accuracy = np.mean(self.episode_accuracies[-10:])
                avg_f1 = np.mean(self.episode_f1_scores[-10:])

                logger.info(
                    f"Episode {episode+1}/{self.n_episodes} | "
                    f"Reward: {episode_reward:.2f} (avg: {avg_reward:.2f}) | "
                    f"Acc: {stats['accuracy']:.3f} (avg: {avg_accuracy:.3f}) | "
                    f"F1: {stats['f1_score']:.3f} (avg: {avg_f1:.3f}) | "
                    f"Epsilon: {self.agent.epsilon:.3f} | "
                    f"Loss: {np.mean(episode_loss) if episode_loss else 0:.4f}"
                )

            # Save model periodically
            if (episode + 1) % self.save_freq == 0:
                self.save_checkpoint(episode + 1)

        logger.info("="*70)
        logger.info("Training completed!")
        logger.info("="*70)

    def save_checkpoint(self, episode: int):
        """Save model checkpoint"""
        checkpoint_path = self.output_dir / f"{self.agent_type}_episode_{episode}.keras"
        self.agent.save(str(checkpoint_path))
        logger.info(f"Saved checkpoint at episode {episode}")

    def save_final_model(self):
        """Save final trained model"""
        model_path = self.output_dir / f"{self.agent_type}_final.keras"
        self.agent.save(str(model_path))

        # Save metrics
        metrics = {
            'agent_type': self.agent_type,
            'n_episodes': self.n_episodes,
            'n_features': self.n_features,
            'final_epsilon': self.agent.epsilon,
            'final_reward': self.episode_rewards[-1] if self.episode_rewards else 0,
            'avg_reward_last_100': np.mean(self.episode_rewards[-100:]) if len(self.episode_rewards) >= 100 else 0,
            'final_accuracy': self.episode_accuracies[-1] if self.episode_accuracies else 0,
            'avg_accuracy_last_100': np.mean(self.episode_accuracies[-100:]) if len(self.episode_accuracies) >= 100 else 0,
            'final_f1': self.episode_f1_scores[-1] if self.episode_f1_scores else 0,
            'avg_f1_last_100': np.mean(self.episode_f1_scores[-100:]) if len(self.episode_f1_scores) >= 100 else 0,
            'training_date': datetime.now().isoformat()
        }

        metrics_path = self.output_dir / f"{self.agent_type}_metrics.json"
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=2)

        logger.info(f"Saved final model to {model_path}")
        logger.info(f"Saved metrics to {metrics_path}")

    def plot_training_results(self):
        """Generate training visualizations"""
        logger.info("Generating training plots...")

        fig, axes = plt.subplots(2, 3, figsize=(18, 10))

        # Episode rewards
        axes[0, 0].plot(self.episode_rewards, alpha=0.6, label='Episode Reward')
        axes[0, 0].plot(self._smooth(self.episode_rewards, 50), linewidth=2, label='Moving Average (50)')
        axes[0, 0].set_title('Episode Rewards', fontsize=12, fontweight='bold')
        axes[0, 0].set_xlabel('Episode')
        axes[0, 0].set_ylabel('Total Reward')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)

        # Accuracy
        axes[0, 1].plot(self.episode_accuracies, alpha=0.6, label='Episode Accuracy')
        axes[0, 1].plot(self._smooth(self.episode_accuracies, 50), linewidth=2, label='Moving Average (50)')
        axes[0, 1].set_title('Detection Accuracy', fontsize=12, fontweight='bold')
        axes[0, 1].set_xlabel('Episode')
        axes[0, 1].set_ylabel('Accuracy')
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3)

        # F1 Score
        axes[0, 2].plot(self.episode_f1_scores, alpha=0.6, label='Episode F1')
        axes[0, 2].plot(self._smooth(self.episode_f1_scores, 50), linewidth=2, label='Moving Average (50)')
        axes[0, 2].set_title('F1 Score', fontsize=12, fontweight='bold')
        axes[0, 2].set_xlabel('Episode')
        axes[0, 2].set_ylabel('F1 Score')
        axes[0, 2].legend()
        axes[0, 2].grid(True, alpha=0.3)

        # Precision
        axes[1, 0].plot(self.episode_precisions, alpha=0.6, label='Episode Precision')
        axes[1, 0].plot(self._smooth(self.episode_precisions, 50), linewidth=2, label='Moving Average (50)')
        axes[1, 0].set_title('Precision', fontsize=12, fontweight='bold')
        axes[1, 0].set_xlabel('Episode')
        axes[1, 0].set_ylabel('Precision')
        axes[1, 0].legend()
        axes[1, 0].grid(True, alpha=0.3)

        # Recall
        axes[1, 1].plot(self.episode_recalls, alpha=0.6, label='Episode Recall')
        axes[1, 1].plot(self._smooth(self.episode_recalls, 50), linewidth=2, label='Moving Average (50)')
        axes[1, 1].set_title('Recall', fontsize=12, fontweight='bold')
        axes[1, 1].set_xlabel('Episode')
        axes[1, 1].set_ylabel('Recall')
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)

        # Training Loss
        axes[1, 2].plot(self.episode_losses, alpha=0.6, label='Episode Loss')
        axes[1, 2].plot(self._smooth(self.episode_losses, 50), linewidth=2, label='Moving Average (50)')
        axes[1, 2].set_title('Training Loss', fontsize=12, fontweight='bold')
        axes[1, 2].set_xlabel('Episode')
        axes[1, 2].set_ylabel('Loss')
        axes[1, 2].legend()
        axes[1, 2].grid(True, alpha=0.3)

        plt.tight_layout()
        plot_path = self.output_dir / f"{self.agent_type}_training_results.png"
        plt.savefig(plot_path, dpi=300, bbox_inches='tight')
        logger.info(f"Saved training plots to {plot_path}")
        plt.close()

    def _smooth(self, data: list, window: int = 50) -> list:
        """Apply moving average smoothing"""
        if len(data) < window:
            return data
        smoothed = []
        for i in range(len(data)):
            start = max(0, i - window + 1)
            smoothed.append(np.mean(data[start:i+1]))
        return smoothed

    def evaluate(self, n_episodes: int = 100):
        """
        Evaluate trained agent

        Args:
            n_episodes: Number of evaluation episodes
        """
        logger.info(f"\nEvaluating agent over {n_episodes} episodes...")

        eval_rewards = []
        eval_accuracies = []
        eval_f1_scores = []

        for episode in range(n_episodes):
            state = self.env.reset()
            episode_reward = 0

            for step in range(self.max_steps):
                # No exploration during evaluation
                action = self.agent.act(state, training=False)
                next_state, reward, done, info = self.env.step(action)

                episode_reward += reward
                state = next_state

                if done:
                    break

            stats = self.env.get_episode_stats()
            eval_rewards.append(episode_reward)
            eval_accuracies.append(stats['accuracy'])
            eval_f1_scores.append(stats['f1_score'])

        logger.info("\n" + "="*70)
        logger.info("EVALUATION RESULTS")
        logger.info("="*70)
        logger.info(f"Average Reward: {np.mean(eval_rewards):.2f} ± {np.std(eval_rewards):.2f}")
        logger.info(f"Average Accuracy: {np.mean(eval_accuracies):.3f} ± {np.std(eval_accuracies):.3f}")
        logger.info(f"Average F1 Score: {np.mean(eval_f1_scores):.3f} ± {np.std(eval_f1_scores):.3f}")
        logger.info("="*70 + "\n")

        return {
            'avg_reward': np.mean(eval_rewards),
            'std_reward': np.std(eval_rewards),
            'avg_accuracy': np.mean(eval_accuracies),
            'std_accuracy': np.std(eval_accuracies),
            'avg_f1': np.mean(eval_f1_scores),
            'std_f1': np.std(eval_f1_scores)
        }


def main():
    """Main training function"""
    parser = argparse.ArgumentParser(description='Train RL Agent for IDS')
    parser.add_argument('--agent', type=str, default='double_dqn',
                        choices=['dqn', 'double_dqn'],
                        help='Type of RL agent')
    parser.add_argument('--episodes', type=int, default=500,
                        help='Number of training episodes')
    parser.add_argument('--steps', type=int, default=1000,
                        help='Maximum steps per episode')
    parser.add_argument('--data', type=str, default='ml-training/data/preprocessed',
                        help='Path to preprocessed data')
    parser.add_argument('--output', type=str, default='rl-module/trained_models',
                        help='Output directory for models')

    args = parser.parse_args()

    # Create trainer
    trainer = RLTrainer(
        agent_type=args.agent,
        n_episodes=args.episodes,
        max_steps=args.steps,
        output_dir=args.output
    )

    # Load data
    trainer.load_training_data(args.data)

    # Train agent
    trainer.train()

    # Save final model
    trainer.save_final_model()

    # Generate plots
    trainer.plot_training_results()

    # Evaluate
    trainer.evaluate(n_episodes=100)

    print("\n" + "="*70)
    print("RL TRAINING COMPLETED!")
    print(f"Model saved to: {trainer.output_dir}")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
