"""
Google Colab RL Training Script for DIDS Project
Run this in Google Colab with GPU runtime for faster training

Instructions:
1. Upload this script to Google Colab
2. Upload the training data files (X_train.npy, X_test.npy, y_train.npy, y_test.npy)
3. Change runtime to GPU (Runtime > Change runtime type > GPU)
4. Run all cells
5. Download the trained model file when complete
"""

# ============================================================================
# INSTALLATION CELL - Run First
# ============================================================================
print("Installing dependencies...")
!pip install tensorflow numpy gymnasium

# ============================================================================
# UPLOAD DATA CELL - Run Second
# ============================================================================
"""
Upload the training_data.tar.gz file from your project root.
The script will automatically extract the data files.

Alternative: Upload these 4 files individually:
- X_train.npy
- X_test.npy
- y_train.npy
- y_test.npy
"""
from google.colab import files
import os
import tarfile

print("Upload training_data.tar.gz (or individual .npy files):")
uploaded = files.upload()

# Check if tar.gz was uploaded and extract it
for filename in uploaded.keys():
    print(f'Uploaded: {filename}')
    if filename.endswith('.tar.gz') or filename.endswith('.tgz'):
        print(f"Extracting {filename}...")
        with tarfile.open(filename, 'r:gz') as tar:
            tar.extractall()
        print("Extraction complete!")

# List extracted files
print("\nAvailable data files:")
import glob
npy_files = glob.glob('*.npy')
for f in npy_files:
    size_mb = os.path.getsize(f) / (1024 * 1024)
    print(f"  - {f} ({size_mb:.2f} MB)")

# ============================================================================
# DQN AGENT IMPLEMENTATION
# ============================================================================
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DQNAgent:
    """Double DQN Agent for IDS"""

    def __init__(self, state_size, action_size, learning_rate=0.001, gamma=0.95,
                 epsilon=1.0, epsilon_decay=0.995, epsilon_min=0.01):
        self.state_size = state_size
        self.action_size = action_size
        self.learning_rate = learning_rate
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_decay = epsilon_decay
        self.epsilon_min = epsilon_min

        # Experience replay buffer
        self.memory = []
        self.memory_size = 10000
        self.batch_size = 64

        # Build networks
        self.model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()

        logger.info(f"Initialized DQN Agent")
        logger.info(f"State size: {state_size}, Action size: {action_size}")

    def _build_model(self):
        """Build neural network"""
        model = keras.Sequential([
            layers.Input(shape=(self.state_size,)),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(64, activation='relu'),
            layers.Dropout(0.2),
            layers.Dense(32, activation='relu'),
            layers.Dense(self.action_size, activation='linear')
        ])
        model.compile(optimizer=keras.optimizers.Adam(learning_rate=self.learning_rate),
                     loss='mse')
        return model

    def update_target_model(self):
        """Copy weights from model to target_model"""
        self.target_model.set_weights(self.model.get_weights())

    def remember(self, state, action, reward, next_state, done):
        """Store experience in replay buffer"""
        if len(self.memory) >= self.memory_size:
            self.memory.pop(0)
        self.memory.append((state, action, reward, next_state, done))

    def act(self, state, training=True):
        """Choose action using epsilon-greedy policy"""
        if training and np.random.random() < self.epsilon:
            return np.random.randint(self.action_size)

        q_values = self.model.predict(state.reshape(1, -1), verbose=0)
        return np.argmax(q_values[0])

    def replay(self):
        """Train on batch from memory"""
        if len(self.memory) < self.batch_size:
            return 0

        # Sample batch
        indices = np.random.choice(len(self.memory), self.batch_size, replace=False)
        batch = [self.memory[i] for i in indices]

        states = np.array([exp[0] for exp in batch])
        actions = np.array([exp[1] for exp in batch])
        rewards = np.array([exp[2] for exp in batch])
        next_states = np.array([exp[3] for exp in batch])
        dones = np.array([exp[4] for exp in batch])

        # Double DQN: use model to select action, target_model to evaluate
        next_q_values_model = self.model.predict(next_states, verbose=0)
        next_actions = np.argmax(next_q_values_model, axis=1)
        next_q_values_target = self.target_model.predict(next_states, verbose=0)

        targets = self.model.predict(states, verbose=0)
        for i in range(self.batch_size):
            if dones[i]:
                targets[i][actions[i]] = rewards[i]
            else:
                targets[i][actions[i]] = rewards[i] + self.gamma * next_q_values_target[i][next_actions[i]]

        history = self.model.fit(states, targets, epochs=1, verbose=0)

        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay

        return history.history['loss'][0]

# ============================================================================
# IDS ENVIRONMENT
# ============================================================================
class IDSEnvironment:
    """IDS Environment for RL Training"""

    def __init__(self, X_data, y_data):
        self.X_data = X_data
        self.y_data = y_data
        self.n_samples = len(X_data)
        self.current_idx = 0
        self.state_size = X_data.shape[1]

        # Episode statistics
        self.reset_stats()
        logger.info(f"Initialized IDS Environment with {self.n_samples} samples")

    def reset_stats(self):
        """Reset episode statistics"""
        self.predictions = []
        self.true_labels = []

    def reset(self):
        """Reset environment"""
        self.current_idx = 0
        self.reset_stats()
        return self.X_data[self.current_idx]

    def step(self, action):
        """Take action in environment"""
        state = self.X_data[self.current_idx]
        true_label = self.y_data[self.current_idx]

        # Actions: 0=allow, 1=monitor, 2=block
        # Map to binary: 0=benign, 1/2=attack
        predicted_label = 1 if action > 0 else 0

        # Calculate reward
        if predicted_label == true_label:
            reward = 1.0  # Correct prediction
        else:
            if true_label == 1 and predicted_label == 0:
                reward = -2.0  # False negative (missed attack)
            else:
                reward = -1.0  # False positive

        # Store for statistics
        self.predictions.append(predicted_label)
        self.true_labels.append(true_label)

        # Move to next sample
        self.current_idx += 1
        done = self.current_idx >= self.n_samples

        if done:
            next_state = np.zeros(self.state_size)
        else:
            next_state = self.X_data[self.current_idx]

        return next_state, reward, done

    def get_episode_stats(self):
        """Calculate episode statistics"""
        if len(self.predictions) == 0:
            return {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1_score': 0}

        predictions = np.array(self.predictions)
        true_labels = np.array(self.true_labels)

        accuracy = np.mean(predictions == true_labels)

        tp = np.sum((predictions == 1) & (true_labels == 1))
        fp = np.sum((predictions == 1) & (true_labels == 0))
        fn = np.sum((predictions == 0) & (true_labels == 1))

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score
        }

# ============================================================================
# TRAINING FUNCTION
# ============================================================================
def train_rl_agent(episodes=100, max_steps=1000):
    """Train RL agent"""

    # Load data
    logger.info("Loading training data...")
    X_train = np.load('X_train.npy')
    y_train = np.load('y_train.npy')

    # Convert to binary labels
    y_train_binary = (y_train > 0).astype(int)

    logger.info(f"Loaded {len(X_train)} training samples")
    logger.info(f"Benign: {np.sum(y_train_binary == 0)}, Attacks: {np.sum(y_train_binary == 1)}")

    # Initialize environment and agent
    env = IDSEnvironment(X_train, y_train_binary)
    agent = DQNAgent(state_size=X_train.shape[1], action_size=3)

    # Training metrics
    episode_rewards = []
    episode_accuracies = []
    episode_f1_scores = []

    logger.info("="*70)
    logger.info(f"Starting RL Training - DOUBLE DQN")
    logger.info("="*70)
    logger.info(f"Episodes: {episodes}")
    logger.info(f"Max steps per episode: {max_steps}")
    logger.info("="*70)

    # Track best performance
    best_f1 = 0
    best_episode = 0

    for episode in range(episodes):
        state = env.reset()
        episode_reward = 0
        episode_losses = []

        # Show progress bar for current episode
        steps_completed = min(max_steps, len(X_train))

        # Run episode
        for step in range(steps_completed):
            # Agent selects action
            action = agent.act(state, training=True)

            # Environment step
            next_state, reward, done = env.step(action)
            episode_reward += reward

            # Store experience
            agent.remember(state, action, reward, next_state, done)

            # Train agent
            loss = agent.replay()
            if loss > 0:
                episode_losses.append(loss)

            state = next_state

            if done:
                break

        # Update target network periodically
        if episode % 10 == 0:
            agent.update_target_model()

        # Get episode statistics
        stats = env.get_episode_stats()

        # Store metrics
        episode_rewards.append(episode_reward)
        episode_accuracies.append(stats['accuracy'])
        episode_f1_scores.append(stats['f1_score'])

        # Track best performance
        if stats['f1_score'] > best_f1:
            best_f1 = stats['f1_score']
            best_episode = episode + 1

        # Log progress EVERY episode with progress bar
        avg_reward = np.mean(episode_rewards[-10:]) if len(episode_rewards) >= 10 else np.mean(episode_rewards)
        avg_accuracy = np.mean(episode_accuracies[-10:]) if len(episode_accuracies) >= 10 else np.mean(episode_accuracies)
        avg_f1 = np.mean(episode_f1_scores[-10:]) if len(episode_f1_scores) >= 10 else np.mean(episode_f1_scores)
        avg_loss = np.mean(episode_losses) if episode_losses else 0

        # Progress bar
        progress = (episode + 1) / episodes
        bar_length = 40
        filled = int(bar_length * progress)
        bar = '█' * filled + '░' * (bar_length - filled)

        # Clear line and print progress (works in Colab)
        print(f"\r[{bar}] {progress*100:.1f}% | "
              f"Episode {episode+1}/{episodes} | "
              f"Reward: {episode_reward:.1f} | "
              f"Acc: {stats['accuracy']:.3f} | "
              f"F1: {stats['f1_score']:.3f} | "
              f"ε: {agent.epsilon:.3f}",
              end='', flush=True)

        # Detailed log every 10 episodes
        if (episode + 1) % 10 == 0:
            print()  # New line after progress bar
            logger.info(
                f"📊 Episode {episode+1}/{episodes} Summary:\n"
                f"   Reward: {episode_reward:.2f} (10-ep avg: {avg_reward:.2f})\n"
                f"   Accuracy: {stats['accuracy']:.3f} (10-ep avg: {avg_accuracy:.3f})\n"
                f"   Precision: {stats['precision']:.3f} | Recall: {stats['recall']:.3f}\n"
                f"   F1 Score: {stats['f1_score']:.3f} (10-ep avg: {avg_f1:.3f})\n"
                f"   Epsilon: {agent.epsilon:.3f} | Loss: {avg_loss:.4f}\n"
                f"   Best F1: {best_f1:.3f} at episode {best_episode}"
            )

    print()  # New line after final progress bar
    logger.info("="*70)
    logger.info("🎉 Training completed!")
    logger.info("="*70)
    logger.info(f"Final 10-Episode Average Accuracy: {np.mean(episode_accuracies[-10:]):.3f}")
    logger.info(f"Final 10-Episode Average F1 Score: {np.mean(episode_f1_scores[-10:]):.3f}")
    logger.info(f"Best F1 Score Achieved: {best_f1:.3f} (Episode {best_episode})")
    logger.info(f"Total Episodes: {episodes}")
    logger.info(f"Final Epsilon: {agent.epsilon:.3f}")
    logger.info("="*70)

    return agent

# ============================================================================
# MAIN TRAINING CELL - Run This to Train
# ============================================================================
# Train the model
trained_agent = train_rl_agent(episodes=100, max_steps=1000)

# Save the trained model
print("\nSaving trained model...")
trained_agent.model.save('double_dqn_final.keras')
print("Model saved as 'double_dqn_final.keras'")

# Save target model too
trained_agent.target_model.save('double_dqn_final_target.keras')
print("Target model saved as 'double_dqn_final_target.keras'")

# ============================================================================
# DOWNLOAD MODEL CELL - Run Last
# ============================================================================
# Download the trained model
print("\nDownloading trained models...")
files.download('double_dqn_final.keras')
files.download('double_dqn_final_target.keras')
print("Download complete! Upload these files to: rl_module/trained_models/")
