import lightgbm as lgb
import pandas as pd
import joblib
import os

class ThreatIntelligenceEngine:
    def __init__(self, model_path="models/lightgbm_model.pkl"):
        self.model_path = model_path
        self.model = None
        self._load_model()

    def _load_model(self):
        """Loads the trained model if it exists."""
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)

    def train_model(self, csv_dataset_path):
        """Trains the LightGBM model on a dataset of feature vectors."""
        print(f"[*] Loading dataset from {csv_dataset_path}...")
        df = pd.read_csv(csv_dataset_path)
        
        # Split features (X) and target label (y)
        X = df.drop('label', axis=1)
        y = df['label']

        # Format for LightGBM
        train_data = lgb.Dataset(X, label=y)

        # Leaf-wise growth parameters optimized for tabular data
        params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.9,
            'verbose': -1
        }

        print("[*] Training LightGBM model...")
        self.model = lgb.train(params, train_data, num_boost_round=100)
        
        # Ensure the models directory exists and save the model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print(f"[+] Model saved to {self.model_path}")

    def get_suspicion_score(self, feature_vector_dict):
        """Executes inference and categorizes the threat level."""
        if not self.model:
            raise Exception("Model not loaded. Please train the model first.")

        # Convert the dictionary into a 2D Pandas DataFrame for the model
        df_features = pd.DataFrame([feature_vector_dict])
        
        # Predict the probability of being malicious
        probability = self.model.predict(df_features)[0]
        score = round(probability, 3)

        # DevSecOps Thresholding Logic
        if score < 0.3:
            classification = "Safe"
        elif 0.3 <= score <= 0.7:
            classification = "Suspicious"
        else:
            classification = "Malicious"

        return {"score": score, "classification": classification}