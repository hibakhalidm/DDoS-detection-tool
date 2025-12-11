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
        - syn_ratio (ratio of SYN-only packets)
        """
        # Ensure appropriate columns exist
        if 'src_ip' not in data.columns:
            return pd.DataFrame()

        # Helper to check for SYN-only packets (SYN set, ACK not set)
        # Scapy flags are often objects, so convert to string. 
        # 'S' is SYN, 'A' is ACK.
        # We want packets where 'S' in flags AND 'A' not in flags.
        def is_syn_only(flags):
            f_str = str(flags)
            return 'S' in f_str and 'A' not in f_str

        # Add is_syn_only column if flags exist
        if 'flags' in data.columns:
            data['is_syn_only'] = data['flags'].apply(is_syn_only).astype(int)
        else:
            data['is_syn_only'] = 0

        # Group by Source IP to get per-IP stats
        grouped = data.groupby('src_ip')
        
        features = pd.DataFrame()
        features['packet_count'] = grouped.size()
        
        if 'pkt_size' in data.columns:
            features['avg_pkt_size'] = grouped['pkt_size'].mean()
        else:
            features['avg_pkt_size'] = 0

        # Calculate SYN ratio
        # Sum of is_syn_only / Count
        features['syn_ratio'] = grouped['is_syn_only'].sum() / grouped.size()

        # Handle NaN values if any (e.g. if division by zero could happen, though groupby size > 0)
        features.fillna(0, inplace=True)
        
        return features
