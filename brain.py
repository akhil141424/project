import numpy as np
import os
import joblib
from sklearn.ensemble import IsolationForest
# We use TensorFlow for the Autoencoder (Deep Learning)
from tensorflow.keras.models import Model, Sequential, load_model
from tensorflow.keras.layers import Dense, Input

class HybridIDS:
    def __init__(self):
        # 10 features: Protocol, Length, TTL, Sport, Dport, Flags, etc.
        self.input_dim = 10 
        self.if_model = None
        self.autoencoder = None
        self.threshold = 0.05  # Reconstruction error threshold for Zero-Day attacks
        
        # Paths to save/load models
        self.model_dir = "models"
        os.makedirs(self.model_dir, exist_ok=True)
        self.if_path = os.path.join(self.model_dir, "isolation_forest.pkl")
        self.ae_path = os.path.join(self.model_dir, "autoencoder.h5")

    def build_models(self):
        """Builds and mocks training for the models if they don't exist."""
        print(">> Initializing Hybrid AI Models...")
        
        # --- Model 1: Deep Autoencoder (For Zero-Day/Complex Patterns) ---
        input_layer = Input(shape=(self.input_dim,))
        # Encoder (Compressing data)
        encoded = Dense(8, activation='relu')(input_layer)
        encoded = Dense(4, activation='relu')(encoded)
        # Decoder (Reconstructing data)
        decoded = Dense(8, activation='relu')(encoded)
        decoded = Dense(self.input_dim, activation='sigmoid')(decoded)

        self.autoencoder = Model(input_layer, decoded)
        self.autoencoder.compile(optimizer='adam', loss='mse')
        
        # --- Model 2: Isolation Forest (For Distinct Anomalies) ---
        self.if_model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

        # --- MOCK TRAINING (To make it work immediately) ---
        # In a real scenario, you would load the CIC-IDS2017 dataset here.
        print(">> Training on mock baseline traffic...")
        X_dummy = np.random.rand(500, self.input_dim)
        self.autoencoder.fit(X_dummy, X_dummy, epochs=5, verbose=0)
        self.if_model.fit(X_dummy)
        
        # Save models (optional, but good practice)
        # self.autoencoder.save(self.ae_path)
        # joblib.dump(self.if_model, self.if_path)
        print(">> AI Engine Ready.")

    def detect(self, features):
        """
        Analyzes a packet's features.
        Returns: (is_threat, severity, description)
        """
        features = np.array(features).reshape(1, -1)

        # 1. Check Isolation Forest (Fast outlier detection)
        if_pred = self.if_model.predict(features)[0] # Returns -1 for anomaly, 1 for normal
        if if_pred == -1:
            return True, "High", "Isolation Forest (Anomaly)"

        # 2. Check Autoencoder (Deep pattern analysis)
        reconstruction = self.autoencoder.predict(features, verbose=0)
        mse = np.mean(np.power(features - reconstruction, 2))
        
        if mse > self.threshold:
            return True, "Medium", f"Autoencoder (Zero-Day Pattern, Error: {mse:.4f})"
        
        return False, "Low", "Normal"

# Create a singleton instance to be used by other files
engine = HybridIDS()
engine.build_models()