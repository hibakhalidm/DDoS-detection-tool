# src/utils/config.py

import os
import json

class Config:
    # Default configuration settings
    DEFAULT_CONFIG = {
        "RAW_DATA_PATH": "data/raw/captured_traffic.csv",
        "PROCESSED_DATA_PATH": "data/processed/processed_data.csv",
        "ANOMALY_DATA_PATH": "data/processed/anomaly_detected.csv",
        "LOG_PATH": "logs/detection.log",
        "THRESHOLD_PACKET_RATE": 100,  # Example threshold for packet rate
        "CONTAMINATION_RATE": 0.01,     # Contamination rate for Isolation Forest
        "MODEL_PATH": "models/trained_model.pkl",
        "ENV": "development"  # Environment type
    }

    def __init__(self, config_file=None):
        self.config = self.DEFAULT_CONFIG.copy()
        if config_file:
            self.load_config(config_file)
        self.override_with_env()

    def load_config(self, config_file):
        """Load configuration from a JSON file."""
        try:
            with open(config_file, 'r') as file:
                file_config = json.load(file)
                self.config.update(file_config)
        except FileNotFoundError:
            print(f"Warning: Configuration file {config_file} not found. Using default settings.")
        except json.JSONDecodeError:
            print("Error: Configuration file is not a valid JSON.")
        except Exception as e:
            print(f"An error occurred while loading the config: {e}")

    def override_with_env(self):
        """Override config values with environment variables if set."""
        for key in self.config.keys():
            env_value = os.getenv(key)
            if env_value is not None:
                # Convert to appropriate types
                if key in ["THRESHOLD_PACKET_RATE", "CONTAMINATION_RATE"]:
                    self.config[key] = float(env_value)
                else:
                    self.config[key] = env_value

    def validate(self):
        """Validate configuration settings."""
        if not os.path.isfile(self.config["RAW_DATA_PATH"]):
            raise ValueError(f"RAW_DATA_PATH does not exist: {self.config['RAW_DATA_PATH']}")
        if not (0 <= self.config["CONTAMINATION_RATE"] <= 1):
            raise ValueError("CONTAMINATION_RATE must be between 0 and 1.")
        if self.config["THRESHOLD_PACKET_RATE"] <= 0:
            raise ValueError("THRESHOLD_PACKET_RATE must be a positive number.")

# Example usage
if __name__ == "__main__":
    config = Config(config_file="../config/config.json")  # Specify your JSON config path
    config.validate()  # Validate configuration
    print("Raw Data Path:", config.config["RAW_DATA_PATH"])
    print("Environment:", config.config["ENV"])
