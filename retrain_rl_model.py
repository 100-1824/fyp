#!/usr/bin/env python3
"""
Quick RL Model Retraining Script
Retrains the Double DQN model with correct 42 features
"""

import json
import logging
import sys
from pathlib import Path

import numpy as np

# Add paths
sys.path.insert(0, str(Path(__file__).parent / "rl_module"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


def main():
    """Retrain RL model with correct features"""
    from rl_module.agents.dqn_agent import DoubleDQNAgent
    from rl_module.environments.ids_environment import IDSEnvironment

    # Load preprocessed data to get correct feature count
    data_path = Path("ml-training/data/preprocessed")
    X_train = np.load(data_path / "X_train.npy")
    y_train = np.load(data_path / "y_train.npy")

    n_features = X_train.shape[1]
    logger.info(f"Training data shape: {X_train.shape}")
    logger.info(f"Number of features: {n_features}")

    # Convert labels to binary (0=benign, 1=attack)
    y_train_binary = (y_train > 0).astype(int)
    logger.info(f"Benign: {np.sum(y_train_binary == 0)}, Attacks: {np.sum(y_train_binary == 1)}")

    # Create environment with correct feature count
    env = IDSEnvironment(n_features=n_features, max_steps=500)
    env.load_data(X_train, y_train_binary)

    # Create Double DQN agent with correct feature count
    agent = DoubleDQNAgent(
        state_size=n_features,  # 42 features
        action_size=3,          # allow, alert, block
        learning_rate=0.001,
        gamma=0.95,
        epsilon=1.0,
        epsilon_min=0.01,
        epsilon_decay=0.99,  # Faster decay for quick training
        batch_size=64,
        buffer_size=5000,
    )

    # Quick training loop (fewer episodes for fast results)
    n_episodes = 100  # Reduced for quick training
    update_target_freq = 5

    logger.info("=" * 60)
    logger.info(f"Starting RL Training with {n_features} features")
    logger.info(f"Episodes: {n_episodes}")
    logger.info("=" * 60)

    episode_rewards = []
    episode_accuracies = []

    for episode in range(n_episodes):
        state = env.reset()
        episode_reward = 0

        for step in range(500):
            action = agent.act(state, training=True)
            next_state, reward, done, info = env.step(action)
            agent.remember(state, action, reward, next_state, done)
            agent.replay()

            episode_reward += reward
            state = next_state

            if done:
                break

        # Update target network
        if episode % update_target_freq == 0:
            agent.update_target_model()

        stats = env.get_episode_stats()
        episode_rewards.append(episode_reward)
        episode_accuracies.append(stats["accuracy"])

        if (episode + 1) % 10 == 0:
            avg_reward = np.mean(episode_rewards[-10:])
            avg_acc = np.mean(episode_accuracies[-10:])
            logger.info(
                f"Episode {episode+1}/{n_episodes} | "
                f"Reward: {episode_reward:.2f} (avg: {avg_reward:.2f}) | "
                f"Accuracy: {stats['accuracy']:.3f} (avg: {avg_acc:.3f}) | "
                f"Epsilon: {agent.epsilon:.3f}"
            )

    # Save the retrained model
    output_path = Path("dids-dashboard/model")
    model_path = output_path / "double_dqn_final.keras"
    target_path = output_path / "double_dqn_final_target.keras"

    agent.save(str(model_path))
    logger.info(f"Saved retrained model to {model_path}")

    # Save model config
    config = {
        "n_features": n_features,
        "n_actions": 3,
        "action_map": {0: "allow", 1: "alert", 2: "block"},
        "training_episodes": n_episodes,
        "final_epsilon": agent.epsilon,
        "final_accuracy": np.mean(episode_accuracies[-10:]),
    }
    config_path = output_path / "double_dqn_config.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    logger.info(f"Saved config to {config_path}")

    logger.info("=" * 60)
    logger.info("RL Model Retraining Complete!")
    logger.info(f"Final Average Accuracy: {np.mean(episode_accuracies[-10:]):.3f}")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
