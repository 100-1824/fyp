#!/usr/bin/env python3
"""
Unit Tests for IDS Environment
"""

import sys
import unittest
from pathlib import Path

import numpy as np

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from rl_module.environments.ids_environment import IDSEnvironment


class TestIDSEnvironment(unittest.TestCase):
    """Test cases for IDS Environment"""

    def setUp(self):
        """Set up test fixtures"""
        # Create sample data
        self.X_train = np.random.random((100, 77))
        self.y_train = np.random.randint(0, 2, 100)
        self.env = IDSEnvironment(self.X_train, self.y_train)

    def test_initialization(self):
        """Test environment initialization"""
        self.assertEqual(self.env.n_features, 77)
        self.assertEqual(self.env.n_actions, 3)
        self.assertEqual(len(self.env.X), 100)
        self.assertEqual(len(self.env.y), 100)

    def test_reset(self):
        """Test environment reset"""
        state = self.env.reset()

        # Should return valid state
        self.assertIsInstance(state, np.ndarray)
        self.assertEqual(state.shape, (1, 77))

        # Index should be reset
        self.assertEqual(self.env.current_index, 0)

        # Metrics should be reset
        self.assertEqual(self.env.true_positives, 0)
        self.assertEqual(self.env.false_positives, 0)
        self.assertEqual(self.env.true_negatives, 0)
        self.assertEqual(self.env.false_negatives, 0)

    def test_step_allow_benign(self):
        """Test step with Allow action on benign traffic"""
        # Force benign traffic
        self.env.y[0] = 0
        state = self.env.reset()

        # Action 0 = Allow
        next_state, reward, done, info = self.env.step(0)

        # Check return types
        self.assertIsInstance(next_state, np.ndarray)
        self.assertIsInstance(reward, (int, float))
        self.assertIsInstance(done, bool)
        self.assertIsInstance(info, dict)

        # Should have positive reward (correct decision)
        self.assertGreater(reward, 0)

        # Should increment true negatives
        self.assertEqual(self.env.true_negatives, 1)

    def test_step_allow_attack(self):
        """Test step with Allow action on attack traffic"""
        # Force attack traffic
        self.env.y[0] = 1
        state = self.env.reset()

        # Action 0 = Allow (wrong decision)
        next_state, reward, done, info = self.env.step(0)

        # Should have negative reward (incorrect decision)
        self.assertLess(reward, 0)

        # Should increment false negatives
        self.assertEqual(self.env.false_negatives, 1)

    def test_step_block_attack(self):
        """Test step with Block action on attack traffic"""
        # Force attack traffic
        self.env.y[0] = 1
        state = self.env.reset()

        # Action 1 = Block
        next_state, reward, done, info = self.env.step(1)

        # Should have positive reward (correct decision)
        self.assertGreater(reward, 0)

        # Should increment true positives
        self.assertEqual(self.env.true_positives, 1)

    def test_step_quarantine_attack(self):
        """Test step with Quarantine action on attack traffic"""
        # Force attack traffic
        self.env.y[0] = 1
        state = self.env.reset()

        # Action 2 = Quarantine
        next_state, reward, done, info = self.env.step(2)

        # Should have positive reward (correct decision)
        self.assertGreater(reward, 0)

        # Should increment true positives
        self.assertEqual(self.env.true_positives, 1)

    def test_episode_completion(self):
        """Test full episode"""
        state = self.env.reset()
        total_reward = 0
        steps = 0

        done = False
        while not done and steps < 200:  # Limit steps for test
            action = np.random.randint(0, 3)
            state, reward, done, info = self.env.step(action)
            total_reward += reward
            steps += 1

        # Should have processed some samples
        self.assertGreater(steps, 0)

        # Episode should end when all samples processed
        if steps < 100:  # If we didn't hit the limit
            self.assertTrue(done)

    def test_metrics_calculation(self):
        """Test metrics calculation"""
        self.env.reset()

        # Simulate some classifications
        self.env.true_positives = 80
        self.env.true_negatives = 70
        self.env.false_positives = 10
        self.env.false_negatives = 5

        accuracy = self.env._calculate_accuracy()
        f1_score = self.env._calculate_f1_score()

        # Accuracy = (TP + TN) / Total = (80 + 70) / 165 = 0.909
        expected_accuracy = 150 / 165
        self.assertAlmostEqual(accuracy, expected_accuracy, places=3)

        # Check F1 score is valid
        self.assertGreaterEqual(f1_score, 0.0)
        self.assertLessEqual(f1_score, 1.0)

    def test_info_dict(self):
        """Test info dictionary contents"""
        state = self.env.reset()
        _, _, _, info = self.env.step(0)

        # Check required keys
        self.assertIn("true_label", info)
        self.assertIn("predicted_label", info)
        self.assertIn("action", info)
        self.assertIn("accuracy", info)
        self.assertIn("f1_score", info)

        # Check types
        self.assertIsInstance(info["true_label"], (int, np.integer))
        self.assertIsInstance(info["predicted_label"], (int, np.integer))
        self.assertIsInstance(info["action"], (int, np.integer))
        self.assertIsInstance(info["accuracy"], float)
        self.assertIsInstance(info["f1_score"], float)

    def test_invalid_action(self):
        """Test invalid action handling"""
        state = self.env.reset()

        # Test with invalid action (should handle gracefully or raise error)
        try:
            # Action outside valid range
            invalid_action = 5
            state, reward, done, info = self.env.step(invalid_action)
            # If it doesn't raise an error, check it handled it somehow
            self.assertIsNotNone(state)
        except (ValueError, IndexError):
            # It's okay if it raises an error for invalid action
            pass

    def test_reward_structure(self):
        """Test reward structure is consistent"""
        self.env.reset()

        # Collect rewards for different scenarios
        rewards = []

        # Benign + Allow (correct)
        self.env.y[0] = 0
        self.env.current_index = 0
        _, r1, _, _ = self.env.step(0)
        rewards.append(("benign_allow", r1))

        # Attack + Block (correct)
        self.env.y[1] = 1
        self.env.current_index = 1
        _, r2, _, _ = self.env.step(1)
        rewards.append(("attack_block", r2))

        # Benign + Block (incorrect)
        self.env.y[2] = 0
        self.env.current_index = 2
        _, r3, _, _ = self.env.step(1)
        rewards.append(("benign_block", r3))

        # Attack + Allow (incorrect)
        self.env.y[3] = 1
        self.env.current_index = 3
        _, r4, _, _ = self.env.step(0)
        rewards.append(("attack_allow", r4))

        # Correct actions should have positive rewards
        self.assertGreater(r1, 0, "Benign + Allow should be positive")
        self.assertGreater(r2, 0, "Attack + Block should be positive")

        # Incorrect actions should have negative rewards
        self.assertLess(r3, 0, "Benign + Block should be negative")
        self.assertLess(r4, 0, "Attack + Allow should be negative")

    def test_state_consistency(self):
        """Test state consistency throughout episode"""
        state1 = self.env.reset()

        # Take a step
        state2, _, _, _ = self.env.step(0)

        # States should have same shape
        self.assertEqual(state1.shape, state2.shape)

        # States should be different (unless we reset)
        if not np.array_equal(state1, state2):
            # This is expected in most cases
            pass


class TestIDSEnvironmentEdgeCases(unittest.TestCase):
    """Test edge cases for IDS Environment"""

    def test_empty_dataset(self):
        """Test with empty dataset"""
        X_empty = np.array([]).reshape(0, 77)
        y_empty = np.array([])

        try:
            env = IDSEnvironment(X_empty, y_empty)
            # Should handle gracefully or raise appropriate error
        except (ValueError, IndexError):
            # Expected behavior for empty dataset
            pass

    def test_single_sample(self):
        """Test with single sample"""
        X_single = np.random.random((1, 77))
        y_single = np.array([0])

        env = IDSEnvironment(X_single, y_single)
        state = env.reset()
        next_state, reward, done, info = env.step(0)

        # Should complete in one step
        self.assertTrue(done or env.current_index >= len(env.X))

    def test_imbalanced_data(self):
        """Test with highly imbalanced data"""
        # 95% benign, 5% attack
        X = np.random.random((100, 77))
        y = np.array([0] * 95 + [1] * 5)

        env = IDSEnvironment(X, y)
        state = env.reset()

        # Should still work correctly
        self.assertIsNotNone(state)
        self.assertEqual(state.shape, (1, 77))


if __name__ == "__main__":
    unittest.main()
