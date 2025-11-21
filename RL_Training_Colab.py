"""
RL Model Training Script for Google Colab
==========================================
Trains Double DQN agent with correct 42 features for DIDS

Instructions:
1. Upload this script to Google Colab
2. Upload your preprocessed data files (X_train.npy, y_train.npy) from:
   ml-training/data/preprocessed/
3. Run all cells
4. Download the generated model files and place them in:
   dids-dashboard/model/
"""

# ============================================================================
# CELL 1: Install dependencies
# ============================================================================
# !pip install tensorflow numpy gymnasium

# ============================================================================
# CELL 2: Imports
# ============================================================================
import json
import logging
import os
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import gymnasium as gym
import numpy as np
import tensorflow as tf
from gymnasium import spaces
from tensorflow import keras
from tensorflow.keras import layers, models

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

print(f"TensorFlow version: {tf.__version__}")
print(f"NumPy version: {np.__version__}")

# ============================================================================
# CELL 3: IDS Environment
# ============================================================================
class IDSEnvironment(gym.Env):
    """Custom Environment for IDS that follows gym interface."""

    def __init__(
        self,
        X: Optional[np.ndarray] = None,
        y: Optional[np.ndarray] = None,
        n_features: int = 42,
        max_steps: int = 1000,
    ):
        super(IDSEnvironment, self).__init__()

        if X is not None:
            n_features = X.shape[1] if len(X.shape) > 1 else n_features

        self.n_features = n_features
        self.max_steps = max_steps
        self.n_actions = 3

        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.Box(
            low=-5.0, high=5.0, shape=(int(n_features),), dtype=np.float32
        )

        self.current_step = 0
        self.episode_rewards = []
        self.episode_actions = []

        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0

        self.data_buffer = deque(maxlen=50000)
        self.label_buffer = deque(maxlen=50000)

        self.current_observation = None
        self.current_label = None

        if X is not None and y is not None:
            self.load_data(X, y)

    def load_data(self, X: np.ndarray, y: np.ndarray):
        self.data_buffer.extend(X)
        self.label_buffer.extend(y)
        logger.info(f"Loaded {len(X)} samples into environment")

    def reset(self) -> np.ndarray:
        self.current_step = 0
        self.episode_rewards = []
        self.episode_actions = []
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0

        if len(self.data_buffer) > 0:
            idx = np.random.randint(0, len(self.data_buffer))
            self.current_observation = np.array(self.data_buffer[idx], dtype=np.float32)
            self.current_label = self.label_buffer[idx]
        else:
            self.current_observation = np.random.randn(self.n_features).astype(np.float32)
            self.current_label = np.random.choice([0, 1])

        return self.current_observation

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        self.current_step += 1
        reward = self._calculate_reward(action, self.current_label)
        self._update_metrics(action, self.current_label)

        self.episode_actions.append(action)
        self.episode_rewards.append(reward)

        done = self.current_step >= self.max_steps

        if not done and len(self.data_buffer) > 0:
            idx = np.random.randint(0, len(self.data_buffer))
            self.current_observation = np.array(self.data_buffer[idx], dtype=np.float32)
            self.current_label = self.label_buffer[idx]

        info = {"accuracy": self._calculate_accuracy(), "f1_score": self._calculate_f1()}
        return self.current_observation, reward, done, info

    def _calculate_reward(self, action: int, true_label: int) -> float:
        is_attack = true_label > 0

        if action == 2:  # Block
            return 10.0 if is_attack else -10.0
        elif action == 1:  # Alert
            return 5.0 if is_attack else -3.0
        else:  # Allow
            return -20.0 if is_attack else 1.0

    def _update_metrics(self, action: int, true_label: int):
        is_attack = true_label > 0
        if action == 2:
            if is_attack:
                self.true_positives += 1
            else:
                self.false_positives += 1
        elif action == 0:
            if is_attack:
                self.false_negatives += 1
            else:
                self.true_negatives += 1

    def _calculate_accuracy(self) -> float:
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total

    def _calculate_precision(self) -> float:
        if (self.true_positives + self.false_positives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    def _calculate_recall(self) -> float:
        if (self.true_positives + self.false_negatives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    def _calculate_f1(self) -> float:
        precision = self._calculate_precision()
        recall = self._calculate_recall()
        if (precision + recall) == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)

    def get_episode_stats(self) -> Dict[str, Any]:
        return {
            "accuracy": self._calculate_accuracy(),
            "precision": self._calculate_precision(),
            "recall": self._calculate_recall(),
            "f1_score": self._calculate_f1(),
        }

# ============================================================================
# CELL 4: Double DQN Agent
# ============================================================================
class DoubleDQNAgent:
    """Double DQN Agent for IDS"""

    def __init__(
        self,
        state_size: int,
        action_size: int,
        learning_rate: float = 0.001,
        gamma: float = 0.95,
        epsilon: float = 1.0,
        epsilon_min: float = 0.01,
        epsilon_decay: float = 0.995,
        batch_size: int = 64,
        buffer_size: int = 10000,
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        self.learning_rate = learning_rate

        self.memory = deque(maxlen=buffer_size)

        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()

    def _build_model(self) -> keras.Model:
        model = models.Sequential([
            layers.Dense(128, activation='relu', input_shape=(self.state_size,)),
            layers.Dropout(0.2),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dense(self.action_size, activation='linear')
        ])
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
            loss='mse'
        )
        return model

    def update_target_model(self):
        self.target_model.set_weights(self.model.get_weights())

    def remember(self, state, action, reward, next_state, done):
        self.memory.append((state, action, reward, next_state, done))

    def act(self, state, training: bool = True):
        if training and np.random.rand() <= self.epsilon:
            return np.random.randint(self.action_size)
        state = np.array(state).reshape(1, -1)
        q_values = self.model.predict(state, verbose=0)
        return np.argmax(q_values[0])

    def replay(self):
        if len(self.memory) < self.batch_size:
            return None

        minibatch = np.random.choice(len(self.memory), self.batch_size, replace=False)
        minibatch = [self.memory[i] for i in minibatch]

        states = np.array([m[0] for m in minibatch])
        actions = np.array([m[1] for m in minibatch])
        rewards = np.array([m[2] for m in minibatch])
        next_states = np.array([m[3] for m in minibatch])
        dones = np.array([m[4] for m in minibatch])

        # Double DQN: use online model to select action, target model to evaluate
        next_q_online = self.model.predict(next_states, verbose=0)
        next_actions = np.argmax(next_q_online, axis=1)

        next_q_target = self.target_model.predict(next_states, verbose=0)
        next_q_values = next_q_target[np.arange(self.batch_size), next_actions]

        targets = rewards + (1 - dones) * self.gamma * next_q_values

        current_q = self.model.predict(states, verbose=0)
        current_q[np.arange(self.batch_size), actions] = targets

        history = self.model.fit(states, current_q, epochs=1, verbose=0)

        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

        return history.history['loss'][0]

    def save(self, filepath: str):
        self.model.save(filepath)
        target_path = filepath.replace('.keras', '_target.keras')
        self.target_model.save(target_path)
        logger.info(f"Saved model to {filepath}")

    def load(self, filepath: str):
        self.model = keras.models.load_model(filepath)
        target_path = filepath.replace('.keras', '_target.keras')
        if os.path.exists(target_path):
            self.target_model = keras.models.load_model(target_path)
        else:
            self.update_target_model()

# ============================================================================
# CELL 5: Upload and Load Data
# ============================================================================
# Upload your files first using Colab's file upload:
# from google.colab import files
# uploaded = files.upload()  # Upload X_train.npy and y_train.npy

# Load the data
print("Loading training data...")
X_train = np.load('X_train.npy')
y_train = np.load('y_train.npy')

print(f"X_train shape: {X_train.shape}")
print(f"y_train shape: {y_train.shape}")

n_features = X_train.shape[1]
print(f"Number of features: {n_features}")

# Convert to binary labels
y_train_binary = (y_train > 0).astype(int)
print(f"Benign samples: {np.sum(y_train_binary == 0)}")
print(f"Attack samples: {np.sum(y_train_binary == 1)}")

# ============================================================================
# CELL 6: Training
# ============================================================================
# Create environment
env = IDSEnvironment(n_features=n_features, max_steps=500)
env.load_data(X_train, y_train_binary)

# Create agent with CORRECT feature count (42)
agent = DoubleDQNAgent(
    state_size=n_features,  # Should be 42
    action_size=3,          # allow, alert, block
    learning_rate=0.001,
    gamma=0.95,
    epsilon=1.0,
    epsilon_min=0.01,
    epsilon_decay=0.995,
    batch_size=64,
    buffer_size=10000,
)

print(f"Agent state size: {agent.state_size}")
print(f"Model input shape: {agent.model.input_shape}")

# Training parameters
N_EPISODES = 25  # Quick training
UPDATE_TARGET_FREQ = 10
SAVE_FREQ = 50

print("=" * 70)
print(f"Starting RL Training with {n_features} features")
print(f"Episodes: {N_EPISODES}")
print("=" * 70)

episode_rewards = []
episode_accuracies = []
episode_f1_scores = []

for episode in range(N_EPISODES):
    state = env.reset()
    episode_reward = 0
    losses = []

    for step in range(500):
        action = agent.act(state, training=True)
        next_state, reward, done, info = env.step(action)
        agent.remember(state, action, reward, next_state, done)

        loss = agent.replay()
        if loss:
            losses.append(loss)

        episode_reward += reward
        state = next_state

        if done:
            break

    if episode % UPDATE_TARGET_FREQ == 0:
        agent.update_target_model()

    stats = env.get_episode_stats()
    episode_rewards.append(episode_reward)
    episode_accuracies.append(stats["accuracy"])
    episode_f1_scores.append(stats["f1_score"])

    if (episode + 1) % 10 == 0:
        avg_reward = np.mean(episode_rewards[-10:])
        avg_acc = np.mean(episode_accuracies[-10:])
        avg_f1 = np.mean(episode_f1_scores[-10:])
        print(
            f"Episode {episode+1}/{N_EPISODES} | "
            f"Reward: {episode_reward:.1f} (avg: {avg_reward:.1f}) | "
            f"Acc: {stats['accuracy']:.3f} (avg: {avg_acc:.3f}) | "
            f"F1: {stats['f1_score']:.3f} (avg: {avg_f1:.3f}) | "
            f"ε: {agent.epsilon:.3f}"
        )

print("=" * 70)
print("Training Complete!")
print(f"Final Average Accuracy: {np.mean(episode_accuracies[-10:]):.3f}")
print(f"Final Average F1 Score: {np.mean(episode_f1_scores[-10:]):.3f}")
print("=" * 70)

# ============================================================================
# CELL 7: Save Model
# ============================================================================
# Save the model
agent.save('double_dqn_final.keras')

# Save config
config = {
    "n_features": int(n_features),
    "n_actions": 3,
    "action_map": {"0": "allow", "1": "alert", "2": "block"},
    "training_episodes": N_EPISODES,
    "final_epsilon": float(agent.epsilon),
    "final_accuracy": float(np.mean(episode_accuracies[-20:])),
    "final_f1_score": float(np.mean(episode_f1_scores[-20:])),
    "training_date": datetime.now().isoformat(),
}

with open('double_dqn_config.json', 'w') as f:
    json.dump(config, f, indent=2)

print("Saved files:")
print("  - double_dqn_final.keras (main model)")
print("  - double_dqn_final_target.keras (target network)")
print("  - double_dqn_config.json (configuration)")

# ============================================================================
# CELL 8: Download Files (for Colab)
# ============================================================================
# Uncomment these lines in Colab to download:
# from google.colab import files
# files.download('double_dqn_final.keras')
# files.download('double_dqn_final_target.keras')
# files.download('double_dqn_config.json')

print("\n" + "=" * 70)
print("DONE! Download these files and place them in:")
print("  dids-dashboard/model/")
print("=" * 70)
