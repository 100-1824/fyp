#!/usr/bin/env python3
"""
Deep Q-Network (DQN) Agent for IDS
Implements DQN with experience replay and target network
"""

import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models, optimizers
from collections import deque
import random
import logging
from typing import List, Tuple, Optional
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)


class ReplayBuffer:
    """Experience replay buffer for DQN"""

    def __init__(self, max_size: int = 10000):
        """
        Initialize replay buffer

        Args:
            max_size: Maximum number of experiences to store
        """
        self.buffer = deque(maxlen=max_size)
        self.max_size = max_size

    def add(self, state: np.ndarray, action: int, reward: float,
            next_state: np.ndarray, done: bool):
        """Add experience to buffer"""
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size: int) -> Tuple:
        """
        Sample random batch from buffer

        Args:
            batch_size: Number of experiences to sample

        Returns:
            Tuple of (states, actions, rewards, next_states, dones)
        """
        batch = random.sample(self.buffer, min(batch_size, len(self.buffer)))

        states = np.array([exp[0] for exp in batch])
        actions = np.array([exp[1] for exp in batch])
        rewards = np.array([exp[2] for exp in batch])
        next_states = np.array([exp[3] for exp in batch])
        dones = np.array([exp[4] for exp in batch])

        return states, actions, rewards, next_states, dones

    def size(self) -> int:
        """Get current buffer size"""
        return len(self.buffer)

    def clear(self):
        """Clear buffer"""
        self.buffer.clear()


class DQNAgent:
    """Deep Q-Network Agent for IDS"""

    def __init__(self,
                 state_size: int,
                 action_size: int = 3,
                 learning_rate: float = 0.001,
                 gamma: float = 0.95,
                 epsilon: float = 1.0,
                 epsilon_min: float = 0.01,
                 epsilon_decay: float = 0.995,
                 batch_size: int = 64,
                 buffer_size: int = 10000):
        """
        Initialize DQN Agent

        Args:
            state_size: Size of state space (number of features)
            action_size: Size of action space (3: Allow, Alert, Block)
            learning_rate: Learning rate for optimizer
            gamma: Discount factor for future rewards
            epsilon: Initial exploration rate
            epsilon_min: Minimum exploration rate
            epsilon_decay: Decay rate for exploration
            batch_size: Size of training batch
            buffer_size: Size of replay buffer
        """
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size

        # Replay buffer
        self.replay_buffer = ReplayBuffer(max_size=buffer_size)

        # Build networks
        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()

        # Training metrics
        self.losses = []
        self.q_values = []

        logger.info("Initialized DQN Agent")
        logger.info(f"State size: {state_size}, Action size: {action_size}")
        logger.info(f"Learning rate: {learning_rate}, Gamma: {gamma}")

    def _build_model(self) -> keras.Model:
        """
        Build neural network for Q-value approximation

        Returns:
            Keras model
        """
        model = models.Sequential([
            layers.InputLayer(input_shape=(self.state_size,)),

            # Deep network for complex pattern recognition
            layers.Dense(256, activation='relu'),
            layers.Dropout(0.2),

            layers.Dense(128, activation='relu'),
            layers.Dropout(0.2),

            layers.Dense(64, activation='relu'),
            layers.Dropout(0.1),

            layers.Dense(32, activation='relu'),

            # Output layer: Q-values for each action
            layers.Dense(self.action_size, activation='linear')
        ])

        model.compile(
            optimizer=optimizers.Adam(learning_rate=self.learning_rate),
            loss='mse',
            metrics=['mae']
        )

        return model

    def update_target_model(self):
        """Copy weights from main model to target model"""
        self.target_model.set_weights(self.model.get_weights())

    def remember(self, state: np.ndarray, action: int, reward: float,
                 next_state: np.ndarray, done: bool):
        """
        Store experience in replay buffer

        Args:
            state: Current state
            action: Action taken
            reward: Reward received
            next_state: Next state
            done: Whether episode is done
        """
        self.replay_buffer.add(state, action, reward, next_state, done)

    def act(self, state: np.ndarray, training: bool = True) -> int:
        """
        Choose action based on epsilon-greedy policy

        Args:
            state: Current state
            training: Whether in training mode (use epsilon-greedy)

        Returns:
            Action to take
        """
        # Epsilon-greedy exploration during training
        if training and np.random.random() < self.epsilon:
            return random.randrange(self.action_size)

        # Exploit: choose action with highest Q-value
        state_tensor = np.array([state])
        q_values = self.model.predict(state_tensor, verbose=0)[0]

        # Store Q-values for analysis
        self.q_values.append(q_values)

        return np.argmax(q_values)

    def replay(self) -> Optional[float]:
        """
        Train on batch from replay buffer

        Returns:
            Training loss or None if buffer too small
        """
        if self.replay_buffer.size() < self.batch_size:
            return None

        # Sample batch from replay buffer
        states, actions, rewards, next_states, dones = self.replay_buffer.sample(self.batch_size)

        # Predict Q-values for current states
        current_q_values = self.model.predict(states, verbose=0)

        # Predict Q-values for next states using target network
        next_q_values = self.target_model.predict(next_states, verbose=0)

        # Calculate target Q-values
        target_q_values = current_q_values.copy()

        for i in range(self.batch_size):
            if dones[i]:
                # If terminal state, target = reward
                target_q_values[i][actions[i]] = rewards[i]
            else:
                # Q-learning update: Q(s,a) = r + gamma * max(Q(s',a'))
                target_q_values[i][actions[i]] = rewards[i] + self.gamma * np.max(next_q_values[i])

        # Train model
        history = self.model.fit(
            states, target_q_values,
            batch_size=self.batch_size,
            epochs=1,
            verbose=0
        )

        loss = history.history['loss'][0]
        self.losses.append(loss)

        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

        return loss

    def train_on_episode(self, n_episodes: int = 1):
        """
        Train for multiple episodes

        Args:
            n_episodes: Number of episodes to train
        """
        for episode in range(n_episodes):
            loss = self.replay()
            if loss is not None:
                logger.info(f"Episode {episode+1}/{n_episodes}, Loss: {loss:.4f}, Epsilon: {self.epsilon:.3f}")

    def save(self, filepath: str):
        """
        Save agent model and parameters

        Args:
            filepath: Path to save model
        """
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        # Save model weights
        self.model.save(str(filepath))

        # Save agent parameters
        params = {
            'state_size': self.state_size,
            'action_size': self.action_size,
            'learning_rate': self.learning_rate,
            'gamma': self.gamma,
            'epsilon': self.epsilon,
            'epsilon_min': self.epsilon_min,
            'epsilon_decay': self.epsilon_decay,
            'batch_size': self.batch_size,
            'losses': self.losses,
        }

        params_file = filepath.parent / f"{filepath.stem}_params.pkl"
        with open(params_file, 'wb') as f:
            pickle.dump(params, f)

        logger.info(f"Saved agent to {filepath}")

    def load(self, filepath: str):
        """
        Load agent model and parameters

        Args:
            filepath: Path to load model from
        """
        filepath = Path(filepath)

        # Load model
        self.model = keras.models.load_model(str(filepath))
        self.target_model = keras.models.load_model(str(filepath))

        # Load parameters
        params_file = filepath.parent / f"{filepath.stem}_params.pkl"
        if params_file.exists():
            with open(params_file, 'rb') as f:
                params = pickle.load(f)

            self.epsilon = params.get('epsilon', self.epsilon)
            self.losses = params.get('losses', [])

        logger.info(f"Loaded agent from {filepath}")

    def get_stats(self) -> dict:
        """Get training statistics"""
        return {
            'epsilon': self.epsilon,
            'buffer_size': self.replay_buffer.size(),
            'avg_loss': np.mean(self.losses[-100:]) if self.losses else 0,
            'total_updates': len(self.losses),
            'avg_q_value': np.mean([np.max(q) for q in self.q_values[-100:]]) if self.q_values else 0
        }


class DoubleDQNAgent(DQNAgent):
    """
    Double DQN Agent - Improved version of DQN
    Uses main network for action selection and target network for evaluation
    """

    def replay(self) -> Optional[float]:
        """
        Train on batch using Double DQN algorithm

        Returns:
            Training loss or None if buffer too small
        """
        if self.replay_buffer.size() < self.batch_size:
            return None

        # Sample batch
        states, actions, rewards, next_states, dones = self.replay_buffer.sample(self.batch_size)

        # Predict Q-values
        current_q_values = self.model.predict(states, verbose=0)

        # Double DQN: Use main network to select action, target network to evaluate
        next_q_values_main = self.model.predict(next_states, verbose=0)
        next_q_values_target = self.target_model.predict(next_states, verbose=0)

        target_q_values = current_q_values.copy()

        for i in range(self.batch_size):
            if dones[i]:
                target_q_values[i][actions[i]] = rewards[i]
            else:
                # Select action using main network
                best_action = np.argmax(next_q_values_main[i])
                # Evaluate using target network
                target_q_values[i][actions[i]] = rewards[i] + self.gamma * next_q_values_target[i][best_action]

        # Train
        history = self.model.fit(
            states, target_q_values,
            batch_size=self.batch_size,
            epochs=1,
            verbose=0
        )

        loss = history.history['loss'][0]
        self.losses.append(loss)

        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

        return loss
