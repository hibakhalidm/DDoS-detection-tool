# src/main.py
import argparse
import logging
import time
import pandas as pd
from src.capture.packet_sniffer import start_sniffing, get_and_clear_captured_data
from src.detection.ml_detection import AnomalyDetector
from src.filtering.ip_filter import check_and_filter_ip
from src.visualize import visualize_data
from src.utils.config import Config

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
    
    # Phase 1: Calibration
    print(f"Calibrating baseline traffic ({calibration_time} seconds)...")
    logging.info("Starting calibration phase...")
    start_sniffing(timeout=calibration_time)
    baseline_data = get_and_clear_captured_data()
    
    if baseline_data.empty:
        logging.warning("No traffic captured during calibration. Training on empty data may fail/skip.")
    
    # Train the baseline
    detector.train_baseline(baseline_data)
    logging.info("Calibration complete. Model trained.")

    # Phase 2: Monitoring Loop
    print(f"Starting Real-Time Monitor (Window: {sniff_time}s)...")
    logging.info("Starting monitoring phase...")
    
    try:
        while True:
            # Sniff a small batch
            start_sniffing(timeout=sniff_time)
            
            # Get data
            batch_data = get_and_clear_captured_data()
            
            if batch_data.empty:
                # Still visualize empty state or just continue?
                # Continue prevents cluttering logs, but visualization might need update.
                continue

            # Detect anomalies
            # Note: We need to handle potential errors if data is malformed, ensuring robustness
            try:
                anomalous_ips = detector.detect_anomalies(batch_data)
            except Exception as e:
                logging.error(f"Error during anomaly detection: {e}")
                anomalous_ips = []

            if anomalous_ips:
                print(f"Anomalies detected: {anomalous_ips}")
                logging.warning(f"Detected {len(anomalous_ips)} suspicious IPs.")
                
                # Filter/Block IPs
                for ip in anomalous_ips:
                    # Calculate packet count for this IP in the current batch for reporting
                    pkt_count = batch_data[batch_data['src_ip'] == ip].shape[0]
                    check_and_filter_ip(ip, packet_count=pkt_count)

            # Update Visualization
            try:
                visualize_data(data_frame=batch_data)
            except Exception as e:
                logging.error(f"Error during visualization: {e}")

            # Optional: Short sleep to prevent tight loop if sniffing is very fast (though sniff timeout handles it)
            
    except KeyboardInterrupt:
        print("\nStopping detection system...")
        logging.info("System stopped by user.")

if __name__ == "__main__":
    arg_parser = setup_arg_parser()
    args = arg_parser.parse_args()
    
    main(sniff_time=args.sniff_time, calibration_time=args.calibration_time)
