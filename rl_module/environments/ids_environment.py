#!/usr/bin/env python3
"""
IDS Reinforcement Learning Environment
Custom OpenAI Gym environment for network intrusion detection
"""

import gym
from gym import spaces
import numpy as np
from typing import Dict, Tuple, Any, Optional
import logging
from collections import deque

logger = logging.getLogger(__name__)


class IDSEnvironment(gym.Env):
    """
    Custom Environment for IDS that follows gym interface.

    State Space: Network flow features (77 features)
    Action Space:
        0 = Allow (benign traffic)
        1 = Alert (suspicious, log and monitor)
        2 = Block (malicious traffic)

    Reward Function:
        +10: Correctly block attack
        +5: Correctly alert on suspicious traffic
        +1: Correctly allow benign traffic
        -10: Block benign traffic (false positive)
        -20: Allow attack (false negative)
        -5: Incorrect alert
    """

    metadata = {'render.modes': ['human', 'console']}

    def __init__(self,
                 n_features: int = 77,
                 attack_threshold: float = 0.7,
                 max_steps: int = 1000):
        """
        Initialize IDS environment

        Args:
            n_features: Number of network flow features
            attack_threshold: Threshold for considering traffic as attack
            max_steps: Maximum steps per episode
        """
        super(IDSEnvironment, self).__init__()

        self.n_features = n_features
        self.attack_threshold = attack_threshold
        self.max_steps = max_steps

        # Action space: 0=Allow, 1=Alert, 2=Block
        self.action_space = spaces.Discrete(3)

        # Observation space: Normalized network features
        self.observation_space = spaces.Box(
            low=-5.0,
            high=5.0,
            shape=(n_features,),
            dtype=np.float32
        )

        # Episode tracking
        self.current_step = 0
        self.episode_rewards = []
        self.episode_actions = []

        # Performance metrics
        self.true_positives = 0
        self.false_positives = 0
        self.true_negatives = 0
        self.false_negatives = 0
        self.alerts_correct = 0
        self.alerts_incorrect = 0

        # Data buffer for training
        self.data_buffer = deque(maxlen=10000)
        self.label_buffer = deque(maxlen=10000)

        # Current state
        self.current_observation = None
        self.current_label = None
        self.current_attack_prob = 0.0

        logger.info(f"Initialized IDS Environment with {n_features} features")

    def load_data(self, X: np.ndarray, y: np.ndarray):
        """
        Load training/testing data into environment

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,) - 0 for benign, >0 for attacks
        """
        logger.info(f"Loading {len(X)} samples into environment")

        self.data_buffer.extend(X)
        self.label_buffer.extend(y)

        logger.info(f"Buffer now contains {len(self.data_buffer)} samples")

    def reset(self) -> np.ndarray:
        """
        Reset the environment to initial state

        Returns:
            Initial observation
        """
        self.current_step = 0
        self.episode_rewards = []
        self.episode_actions = []

        # Get random sample from buffer
        if len(self.data_buffer) > 0:
            idx = np.random.randint(0, len(self.data_buffer))
            self.current_observation = np.array(self.data_buffer[idx], dtype=np.float32)
            self.current_label = self.label_buffer[idx]
        else:
            # Generate random observation if no data loaded
            self.current_observation = np.random.randn(self.n_features).astype(np.float32)
            self.current_label = np.random.choice([0, 1])

        # Simulate attack probability (in real scenario, this comes from ML model)
        self.current_attack_prob = self._simulate_attack_probability()

        return self.current_observation

    def _simulate_attack_probability(self) -> float:
        """
        Simulate attack probability based on label
        For training with labeled data
        """
        if self.current_label == 0:
            # Benign traffic: low attack probability with some noise
            return np.random.uniform(0.0, 0.3)
        else:
            # Attack traffic: high attack probability with some noise
            return np.random.uniform(0.6, 1.0)

    def step(self, action: int) -> Tuple[np.ndarray, float, bool, Dict[str, Any]]:
        """
        Execute one time step

        Args:
            action: Action to take (0=Allow, 1=Alert, 2=Block)

        Returns:
            observation: Next state
            reward: Reward for the action
            done: Whether episode is finished
            info: Additional information
        """
        self.current_step += 1

        # Calculate reward based on action and true label
        reward = self._calculate_reward(action, self.current_label, self.current_attack_prob)

        # Update metrics
        self._update_metrics(action, self.current_label)

        # Store action and reward
        self.episode_actions.append(action)
        self.episode_rewards.append(reward)

        # Check if episode is done
        done = self.current_step >= self.max_steps or len(self.data_buffer) == 0

        # Get next observation
        if not done and len(self.data_buffer) > 0:
            idx = np.random.randint(0, len(self.data_buffer))
            self.current_observation = np.array(self.data_buffer[idx], dtype=np.float32)
            self.current_label = self.label_buffer[idx]
            self.current_attack_prob = self._simulate_attack_probability()

        # Prepare info dict
        info = {
            'true_label': self.current_label,
            'attack_probability': self.current_attack_prob,
            'action_taken': action,
            'step': self.current_step,
            'episode_reward': sum(self.episode_rewards),
            'accuracy': self._calculate_accuracy(),
            'precision': self._calculate_precision(),
            'recall': self._calculate_recall(),
            'f1_score': self._calculate_f1()
        }

        return self.current_observation, reward, done, info

    def _calculate_reward(self, action: int, true_label: int, attack_prob: float) -> float:
        """
        Calculate reward based on action and ground truth

        Args:
            action: Action taken (0=Allow, 1=Alert, 2=Block)
            true_label: True label (0=Benign, >0=Attack)
            attack_prob: Estimated attack probability

        Returns:
            Reward value
        """
        is_attack = true_label > 0

        if action == 2:  # Block
            if is_attack:
                # Correctly blocked attack - HIGH REWARD
                reward = 10.0
            else:
                # Blocked benign traffic - FALSE POSITIVE PENALTY
                reward = -10.0

        elif action == 1:  # Alert
            if is_attack:
                # Correctly alerted on attack - MEDIUM REWARD
                reward = 5.0
            elif attack_prob > 0.4:
                # Alert on suspicious traffic - SMALL REWARD
                reward = 2.0
            else:
                # Alert on clearly benign traffic - SMALL PENALTY
                reward = -3.0

        else:  # action == 0: Allow
            if is_attack:
                # Allowed attack - FALSE NEGATIVE PENALTY (WORST)
                reward = -20.0
            else:
                # Correctly allowed benign traffic - SMALL REWARD
                reward = 1.0

        return reward

    def _update_metrics(self, action: int, true_label: int):
        """Update performance metrics"""
        is_attack = true_label > 0
        is_blocked = action == 2
        is_alerted = action == 1
        is_allowed = action == 0

        # For binary classification metrics (Block vs Allow, treating Alert as monitoring)
        if is_blocked:
            if is_attack:
                self.true_positives += 1
            else:
                self.false_positives += 1
        elif is_allowed:
            if is_attack:
                self.false_negatives += 1
            else:
                self.true_negatives += 1
        elif is_alerted:
            if is_attack:
                self.alerts_correct += 1
            else:
                self.alerts_incorrect += 1

    def _calculate_accuracy(self) -> float:
        """Calculate current accuracy"""
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total

    def _calculate_precision(self) -> float:
        """Calculate current precision"""
        if (self.true_positives + self.false_positives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    def _calculate_recall(self) -> float:
        """Calculate current recall"""
        if (self.true_positives + self.false_negatives) == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    def _calculate_f1(self) -> float:
        """Calculate F1 score"""
        precision = self._calculate_precision()
        recall = self._calculate_recall()
        if (precision + recall) == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)

    def render(self, mode='human'):
        """Render the environment"""
        if mode == 'human' or mode == 'console':
            print(f"\n{'='*60}")
            print(f"Step: {self.current_step}/{self.max_steps}")
            print(f"Episode Reward: {sum(self.episode_rewards):.2f}")
            print(f"Accuracy: {self._calculate_accuracy():.3f}")
            print(f"Precision: {self._calculate_precision():.3f}")
            print(f"Recall: {self._calculate_recall():.3f}")
            print(f"F1 Score: {self._calculate_f1():.3f}")
            print(f"TP: {self.true_positives}, FP: {self.false_positives}")
            print(f"TN: {self.true_negatives}, FN: {self.false_negatives}")
            print(f"Alerts Correct: {self.alerts_correct}, Incorrect: {self.alerts_incorrect}")
            print(f"{'='*60}\n")

    def get_episode_stats(self) -> Dict[str, Any]:
        """Get episode statistics"""
        return {
            'total_reward': sum(self.episode_rewards),
            'average_reward': np.mean(self.episode_rewards) if self.episode_rewards else 0,
            'steps': self.current_step,
            'accuracy': self._calculate_accuracy(),
            'precision': self._calculate_precision(),
            'recall': self._calculate_recall(),
            'f1_score': self._calculate_f1(),
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'true_negatives': self.true_negatives,
            'false_negatives': self.false_negatives,
            'alerts_correct': self.alerts_correct,
            'alerts_incorrect': self.alerts_incorrect,
            'actions': {
                'allow': self.episode_actions.count(0),
                'alert': self.episode_actions.count(1),
                'block': self.episode_actions.count(2)
            }
        }

    def close(self):
        """Clean up environment"""
        pass
