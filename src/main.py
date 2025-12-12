# src/main.py
import os
import argparse
import logging
import time
import pandas as pd
from datetime import datetime, timedelta
from src.capture.packet_sniffer import start_sniffing, get_and_clear_captured_data
from src.detection.ml_detection import AnomalyDetector
from src.visualize import visualize_data
from src.utils.detection_log import log_detection
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_arg_parser():
    """Set up command line argument parser."""
    parser = argparse.ArgumentParser(description="Real-Time DDoS Detection System")
    parser.add_argument('--sniff_time', type=int, default=2, help='Duration of sniffing window in seconds')
    parser.add_argument('--calibration_time', type=int, default=10, help='Duration of calibration phase in seconds')
    return parser

def main(sniff_time, calibration_time):
    # Initialize Detector
    detector = AnomalyDetector()
    
    # Initialize Rolling History (for visualization)
    # Columns: timestamp, packet_count, anomalies_detected
    history_df = pd.DataFrame(columns=['timestamp', 'packet_count'])
    
    # Phase 1: Calibration
    print(f"Calibrating baseline traffic ({calibration_time} seconds)...")
    logging.info("Starting calibration phase...")
    start_sniffing(timeout=calibration_time)
    baseline_data = get_and_clear_captured_data()
    
    if baseline_data.empty:
        logging.warning("No traffic captured during calibration. Training on empty data may fail/skip.")
    else:
        # Pre-populate history with baseline? Optional.
        pass
    
    # Train the baseline
    detector.train_baseline(baseline_data)
    logging.info("Calibration complete. Model trained.")

    # Phase 2: Monitoring Loop
    print(f"Starting Real-Time Monitor (Window: {sniff_time}s)...")
    logging.info("Starting monitoring phase...")
    
    try:
        # Initialize Simulation Results File
        results_path = "data/processed/simulation_results.csv"
        os.makedirs(os.path.dirname(results_path), exist_ok=True)
        if not os.path.exists(results_path):
             with open(results_path, 'w') as f:
                 f.write("timestamp,src_ip,is_attacker,predicted_anomaly,risk_level\n")

        while True:
            # Sniff a small batch
            start_sniffing(timeout=sniff_time)
            
            # Get data
            batch_data = get_and_clear_captured_data()
            current_time = datetime.now()
            
            # Update History
            batch_count = len(batch_data)
            new_row = pd.DataFrame([{'timestamp': current_time, 'packet_count': batch_count}])
            history_df = pd.concat([history_df, new_row], ignore_index=True)
            
            # Keep only last 60 seconds (approx)
            cutoff_time = current_time - timedelta(seconds=60)
            history_df = history_df[history_df['timestamp'] > cutoff_time]
            
            if batch_data.empty:
                # Still visualize the history even if current batch is empty
                try:
                    visualize_data(data_frame=history_df)
                except Exception as e:
                    logging.error(f"Error during visualization (empty batch): {e}")
                continue

            # Detect anomalies
            try:
                # Now returns profiles: [{'src_ip': '...', 'risk_level': '...', ...}]
                anomaly_profiles = detector.detect_anomalies(batch_data)
                
                # Extract simple list of IPs for quick lookup
                anomalous_ips = {p['src_ip'] for p in anomaly_profiles}
                
                # --- Accuracy Metrics Recording ---
                # Iterate over ALL unique IPs in the batch to record True/False Positives/Negatives
                unique_ips = batch_data['src_ip'].unique()
                with open(results_path, 'a') as f:
                    for ip in unique_ips:
                        # Ground Truth Assumption
                        is_attacker = 1 if ip.startswith("192.168.1.") else 0
                        
                        # Prediction
                        predicted = 1 if ip in anomalous_ips else 0
                        
                        # Risk (if anomalous)
                        risk = "None"
                        for p in anomaly_profiles:
                             if p['src_ip'] == ip:
                                  risk = p['risk_level']
                                  break
                        
                        f.write(f"{current_time},{ip},{is_attacker},{predicted},{risk}\n")
                # ----------------------------------

            except Exception as e:
                logging.error(f"Error during anomaly detection: {e}")
                anomaly_profiles = []

            if anomaly_profiles:
                logging.warning(f"Detected {len(anomaly_profiles)} suspicious IPs.")
                
                # Filter/Block IPs and Log Reason
                for profile in anomaly_profiles:
                    ip = profile['src_ip']
                    
                    # Extract features for this IP to find the reason
                    # We need the grouped data or filter the original batch
                    # This is slightly inefficient but clear.
                    ip_data = batch_data[batch_data['src_ip'] == ip]
                    
                    # We need to re-extract features (or better, have detector return them).
                    # Since detector doesn't return them, we use a public helper or just re-calculate locally if needed.
                    # But actually `get_anomaly_reason` expects features. 
                    # Let's assume we can get them.
                    # Ideally `detect_anomalies` should return them. 
                    # Since I updated `detect_anomalies` to NOT return them, I have to re-extract.
                    # Warning: This calls the internal method _extract_features again. 
                    # Ideally we refactor to avoid double extraction, but for now this is robust.
                    ip_features_df = detector._extract_features(ip_data)
                    
                    if not ip_features_df.empty:
                         # It's a dataframe with one row (indexed by src_ip)
                         ip_features = ip_features_df.iloc[0]
                         reason = detector.get_anomaly_reason(ip_features)
                    else:
                         reason = "Unknown"

                    # Calculate packet count for this IP in the current batch
                    pkt_count = ip_data.shape[0]
                    
                    # Log with full context
                    log_detection(ip, pkt_count, detection_method="ML_IsolationForest", reason=reason, profile=profile)

            # Update Visualization with History
            try:
                visualize_data(data_frame=history_df)
            except Exception as e:
                logging.error(f"Error during visualization: {e}")
            
    except KeyboardInterrupt:
        print("\nStopping detection system...")
        logging.info("System stopped by user.")

if __name__ == "__main__":
    arg_parser = setup_arg_parser()
    args = arg_parser.parse_args()
    
    main(sniff_time=args.sniff_time, calibration_time=args.calibration_time)
