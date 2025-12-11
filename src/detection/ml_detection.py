# src/detection/ml_detection.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, contamination=0.01):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False

    def train_baseline(self, data):
        """
        Fits an Isolation Forest model on 'clean' traffic data.
        Expects a DataFrame with packet info.
        """
        if data.empty:
            print("No data for calibration.")
            return

        features = self._extract_features(data)
        if features.empty:
            print("Not enough data to extract features.")
            return

        self.model.fit(features)
        self.is_trained = True
        print(f"Bseline trained on {len(features)} unique IPs.")

    def detect_anomalies(self, data):
        """
        Detects anomalies in the provided data batch.
        Returns a list of suspicious IPs.
        """
        if not self.is_trained:
            print("Model not trained yet. Skipping detection.")
            return []

        if data.empty:
            return []

        features = self._extract_features(data)
        if features.empty:
            return []

        predictions = self.model.predict(features)
        # -1 indicates anomaly
        anomalies_mask = predictions == -1
        suspicious_ips = features.index[anomalies_mask].tolist()
        
        return suspicious_ips

    def _extract_features(self, data):
        """
        Aggregates data by src_ip and calculates features:
        - packet_count (volume)
        - avg_pkt_size
        - syn_ratio (if 'flags' or 'is_syn' available)
        """
        # Ensure appropriate columns exist
        if 'src_ip' not in data.columns:
            return pd.DataFrame()

        # Group by Source IP to get per-IP stats
        grouped = data.groupby('src_ip')
        
        features = pd.DataFrame()
        features['packet_count'] = grouped.size()
        
        if 'pkt_size' in data.columns:
            features['avg_pkt_size'] = grouped['pkt_size'].mean()
        else:
            features['avg_pkt_size'] = 0

        # Calculate SYN ratio if possible
        if 'is_syn' in data.columns:
            features['syn_ratio'] = grouped['is_syn'].mean()
        elif 'flags' in data.columns:
             # Basic check for 'S' in flags if it's a string representation
             # This depends on how flags are stored. 
             # Assuming 'is_syn' is already preprocessed would be safer if that's what main.py provides,
             # but let's try to handle raw flags if is_syn is missing.
             # For now, we will assume is_syn is preferred as per previous code.
             features['syn_ratio'] = 0
        else:
             features['syn_ratio'] = 0

        # Handle NaN values if any
        features.fillna(0, inplace=True)
        
        return features
