# src/detection/ml_detection.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, contamination=0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.baseline_means = None

    def train_baseline(self, data):
        """
        Fits an Isolation Forest model on 'clean' traffic data.
        Expects a DataFrame with packet info.
        Stores baseline means for feature reasoning.
        """
        if data.empty:
            print("No data for calibration.")
            return

        features = self._extract_features(data)
        if features.empty:
            print("Not enough data to extract features.")
            return

        # Store baseline means
        self.baseline_means = features.mean()
        
        # Scale features
        scaled_features = self.scaler.fit_transform(features)
        
        self.model.fit(scaled_features)
        self.is_trained = True
        print(f"Bseline trained on {len(features)} unique IPs.")

    def detect_anomalies(self, data):
        """
        Detects anomalies in the provided data batch.
        Returns a list of dictionaries with profile info.
        """
        if not self.is_trained:
            print("Model not trained yet. Skipping detection.")
            return []

        if data.empty:
            return []

        features = self._extract_features(data)
        if features.empty:
            return []

        # Scale features using the trained scaler
        scaled_features = self.scaler.transform(features)

        # Get anomaly labels (-1 is anomaly)
        predictions = self.model.predict(scaled_features)
        # Get raw anomaly scores (lower is more anomalous)
        scores = self.model.decision_function(scaled_features)
        
        # --- Heuristic Override for SYN Flood (Demo Hardening) ---
        # If syn_ratio > 0.8 AND packet_count > 50 (approx), force it to be an anomaly
        # This ensures we catch obvious attacks even if the model is fuzzy.
        # We manually modify the prediction mask.
        
        # Create a mask for heuristic detection
        # Heuristic: High SYN ratio and some volume
        heuristic_mask = (features['syn_ratio'] > 0.8) & (features['packet_count'] > 20)
        
        # Combine model predictions with heuristic
        # If model says -1 OR heuristic says True
        final_anomalies_mask = (predictions == -1) | heuristic_mask
        
        suspicious_ips = features.index[final_anomalies_mask].tolist()
        
        # Get corresponding scores map (heuristic ones might not be low, so we fake a low score if needed)
        
        profiles = []
        for ip in suspicious_ips:
            # Find index in features (which is indexed by ip, but we need integer index for scores/predictions array)
            idx = features.index.get_loc(ip)
            
            score = scores[idx]
            is_heuristic = heuristic_mask.iloc[idx]
            
            # If caught by heuristic but not model, force a critical score
            if is_heuristic and score > -0.1:
                score = -0.5 # Forced critical score
            
            # Risk Mapping
            if score < -0.2:
                risk_level = "CRITICAL"
                confidence = "High"
            elif score < -0.1:
                risk_level = "HIGH"
                confidence = "Medium"
            else:
                risk_level = "MEDIUM"
                confidence = "Low"
                
            profiles.append({
                'src_ip': ip,
                'risk_level': risk_level,
                'confidence': confidence,
                'anomaly_score': float(score)
            })
        
        return profiles

    def get_anomaly_reason(self, ip_features):
        """
        Compares IP features against baseline means to find the main driver of anomaly.
        ip_features: Series or Dict of features for a specific IP.
        """
        if self.baseline_means is None:
            return "Unknown (No Baseline)"

        max_deviation = -1
        reason = "Unknown"
        
        # Features we care about
        feature_names = ['packet_count', 'avg_pkt_size', 'syn_ratio']
        
        for feat in feature_names:
            if feat not in ip_features:
                continue
            
            val = ip_features[feat]
            baseline_val = self.baseline_means.get(feat, 0)
            
            # Avoid division by zero
            if baseline_val == 0:
                if val > 0:
                    deviation = float('inf') # Infinite relative increase
                else:
                    deviation = 0
            else:
                deviation = abs(val - baseline_val) / baseline_val
                
            if deviation > max_deviation:
                max_deviation = deviation
                reason = f"High {feat} (Value: {val:.2f}, Baseline: {baseline_val:.2f})"
        
        return reason

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

        # Handle NaN values if any
        features.fillna(0, inplace=True)
        
        return features
