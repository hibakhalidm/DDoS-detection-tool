# src/utils/detection_log.py
import logging
import json
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler

# Set up a rotating file handler for logs
# Ensure absolute path irrespective of where script is run from
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
log_file_path = os.path.join(PROJECT_ROOT, "logs", "detection.log")
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
        
    def log_detection(self, src_ip, packet_rate, detection_method='Threshold', reason=None, profile=None):
        """Log DDoS detection information in a structured format."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'packet_rate': packet_rate,
            'detection_method': detection_method,
            'message': 'DDoS Detected!'
        }
        
        if reason:
             log_entry['reason'] = reason
        if profile:
             log_entry['profile'] = profile
        
        # Log as JSON string
        self.logger.info(json.dumps(log_entry))
        
        # Enhanced console output
        console_msg = f"[ALERT] IP: {src_ip} | Method: {detection_method}"
        if reason:
            console_msg += f" | Reason: {reason}"
        if profile:
             risk = profile.get('risk_level', 'UNKNOWN')
             console_msg += f" | Risk: {risk}"
             
        print(console_msg)

# Initialize the logger
detection_logger = DetectionLogger()

# Wrapper function for logging
def log_detection(src_ip, packet_rate, detection_method='Threshold', reason=None, profile=None):
    detection_logger.log_detection(src_ip, packet_rate, detection_method, reason, profile)

