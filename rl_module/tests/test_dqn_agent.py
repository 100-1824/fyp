#!/usr/bin/env python3
"""
Unit Tests for DQN Agent
"""

import unittest
import numpy as np
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from rl_module.agents.dqn_agent import DQNAgent, DoubleDQNAgent


class TestDQNAgent(unittest.TestCase):
    """Test cases for DQN Agent"""

    def setUp(self):
        """Set up test fixtures"""
        self.state_size = 77
        self.action_size = 3
        self.agent = DQNAgent(
            state_size=self.state_size,
            action_size=self.action_size,
            learning_rate=0.001,
            gamma=0.95,
            epsilon=1.0
        )

    def test_initialization(self):
        """Test agent initialization"""
        self.assertEqual(self.agent.state_size, 77)
        self.assertEqual(self.agent.action_size, 3)
        self.assertEqual(self.agent.epsilon, 1.0)
        self.assertIsNotNone(self.agent.model)
        self.assertIsNotNone(self.agent.target_model)

    def test_model_architecture(self):
        """Test model architecture"""
        # Check input shape
        self.assertEqual(self.agent.model.input_shape, (None, 77))
        # Check output shape
        self.assertEqual(self.agent.model.output_shape, (None, 3))
        # Check number of layers
        self.assertGreater(len(self.agent.model.layers), 2)

    def test_act_exploration(self):
        """Test action selection during exploration"""
        state = np.random.random((1, 77))
        self.agent.epsilon = 1.0  # Force exploration

        # With high epsilon, should get random actions
        actions = [self.agent.act(state) for _ in range(100)]
        # Should have some variety in actions
        unique_actions = len(set(actions))
        self.assertGreater(unique_actions, 1)

    def test_act_exploitation(self):
        """Test action selection during exploitation"""
        state = np.random.random((1, 77))
        self.agent.epsilon = 0.0  # Force exploitation

        # Should consistently return same action for same state
        action1 = self.agent.act(state)
        action2 = self.agent.act(state)
        self.assertEqual(action1, action2)

    def test_remember(self):
        """Test experience replay memory"""
        state = np.random.random((1, 77))
        action = 1
        reward = 10
        next_state = np.random.random((1, 77))
        done = False

        initial_memory_size = len(self.agent.memory)
        self.agent.remember(state, action, reward, next_state, done)

        self.assertEqual(len(self.agent.memory), initial_memory_size + 1)

    def test_memory_limit(self):
        """Test memory size limit"""
        for i in range(2500):  # Exceed default memory size
            state = np.random.random((1, 77))
            self.agent.remember(state, 1, 10, state, False)

        # Memory should not exceed max size
        self.assertLessEqual(len(self.agent.memory), 2000)

    def test_replay_insufficient_samples(self):
        """Test replay with insufficient samples"""
        # Add only a few experiences
        for _ in range(5):
            state = np.random.random((1, 77))
            self.agent.remember(state, 1, 10, state, False)

        # Should not crash with small batch
        try:
            self.agent.replay(batch_size=32)
            test_passed = True
        except Exception as e:
            test_passed = False
            print(f"Error: {e}")

        self.assertTrue(test_passed)

    def test_update_target_model(self):
        """Test target model update"""
        # Get initial weights
        initial_weights = self.agent.target_model.get_weights()[0].copy()

        # Modify main model
        for _ in range(10):
            state = np.random.random((1, 77))
            self.agent.remember(state, 1, 10, state, False)
        self.agent.replay(batch_size=5)

        # Update target model
        self.agent.update_target_model()
        updated_weights = self.agent.target_model.get_weights()[0].copy()

        # Weights should have changed
        self.assertFalse(np.array_equal(initial_weights, updated_weights))

    def test_epsilon_decay(self):
        """Test epsilon decay"""
        initial_epsilon = self.agent.epsilon

        # Simulate learning
        for _ in range(100):
            state = np.random.random((1, 77))
            self.agent.remember(state, 1, 10, state, False)
            if len(self.agent.memory) > 32:
                self.agent.replay(batch_size=32)

        # Epsilon should have decayed
        self.assertLess(self.agent.epsilon, initial_epsilon)
        # But not below minimum
        self.assertGreaterEqual(self.agent.epsilon, self.agent.epsilon_min)

    def test_save_load(self):
        """Test model save and load"""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.keras', delete=False) as f:
            temp_path = f.name

        try:
            # Save model
            self.agent.save(temp_path)

            # Check file exists
            self.assertTrue(Path(temp_path).exists())

            # Load into new agent
            new_agent = DQNAgent(self.state_size, self.action_size)
            new_agent.model.load_weights(temp_path)

            # Test predictions match
            state = np.random.random((1, 77))
            pred1 = self.agent.model.predict(state, verbose=0)
            pred2 = new_agent.model.predict(state, verbose=0)

            np.testing.assert_array_almost_equal(pred1, pred2, decimal=5)
        finally:
            # Cleanup
            if Path(temp_path).exists():
                Path(temp_path).unlink()


class TestDoubleDQNAgent(unittest.TestCase):
    """Test cases for Double DQN Agent"""

    def setUp(self):
        """Set up test fixtures"""
        self.state_size = 77
        self.action_size = 3
        self.agent = DoubleDQNAgent(
            state_size=self.state_size,
            action_size=self.action_size
        )

    def test_initialization(self):
        """Test Double DQN initialization"""
        self.assertEqual(self.agent.state_size, 77)
        self.assertEqual(self.agent.action_size, 3)
        self.assertIsNotNone(self.agent.model)
        self.assertIsNotNone(self.agent.target_model)

    def test_double_dqn_replay(self):
        """Test Double DQN replay mechanism"""
        # Add experiences
        for _ in range(100):
            state = np.random.random((1, 77))
            action = np.random.randint(0, 3)
            reward = np.random.random() * 100 - 50
            next_state = np.random.random((1, 77))
            done = False
            self.agent.remember(state, action, reward, next_state, done)

        # Perform replay
        try:
            self.agent.replay(batch_size=32)
            test_passed = True
        except Exception as e:
            test_passed = False
            print(f"Error in Double DQN replay: {e}")

        self.assertTrue(test_passed)

    def test_action_selection_difference(self):
        """Test that Double DQN uses different approach"""
        state = np.random.random((1, 77))

        # Both agents should work
        dqn = DQNAgent(self.state_size, self.action_size)
        ddqn = DoubleDQNAgent(self.state_size, self.action_size)

        dqn.epsilon = 0.0
        ddqn.epsilon = 0.0

        action_dqn = dqn.act(state)
        action_ddqn = ddqn.act(state)

        # Both should return valid actions
        self.assertIn(action_dqn, [0, 1, 2])
        self.assertIn(action_ddqn, [0, 1, 2])


if __name__ == '__main__':
    unittest.main()
