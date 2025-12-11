# src/utils/detection_log.py
import logging
import json
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Set up a rotating file handler for logs
log_file_path = "../logs/detection.log"
os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

# Create a custom logger
class DetectionLogger:
    def __init__(self):
        self.logger = logging.getLogger("DDoS Detection Logger")
        self.logger.setLevel(logging.INFO)
        
        # Create a rotating file handler
        handler = RotatingFileHandler(log_file_path, maxBytes=5*1024*1024, backupCount=5)  # 5 MB limit, keep 5 backups
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        
    def log_detection(self, src_ip, packet_rate, detection_method='Threshold'):
        """Log DDoS detection information in a structured format."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'packet_rate': packet_rate,
            'detection_method': detection_method,
            'message': 'DDoS Detected!'
        }
        
        # Log as JSON string
        self.logger.info(json.dumps(log_entry))
        print(json.dumps(log_entry))  # Print to console for immediate feedback

# Initialize the logger
detection_logger = DetectionLogger()

# Wrapper function for logging
def log_detection(src_ip, packet_rate, detection_method='Threshold'):
    detection_logger.log_detection(src_ip, packet_rate, detection_method)

