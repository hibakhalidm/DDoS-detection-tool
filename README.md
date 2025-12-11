# DDoS Detection Tool

This project is designed to detect Distributed Denial of Service (DDoS) attacks using various machine learning algorithms. The tool captures network packets, processes the data, applies machine learning models, and visualizes the results.

## Features
- Real-time packet capture
- Feature extraction from network packets
- Machine learning-based DDoS detection
- Visualization of network traffic

## Requirements

The following Python packages are required to run this project:
- scapy
- pandas
- numpy
- scikit-learn
- joblib
- matplotlib
- logzero
- datetime

You can install them using the following command:
```bash
pip install -r requirements.txt
```

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/hibakhalidm/DDoS-detection-tool.git
    cd DDoS-detection-tool
    ```

2. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Quick Start: Detect and Simulate

1. **Start the Detector**
     - Open a terminal and run:
         ```bash
         python -m src.main --calibration_time 10 --sniff_time 2
         ```
     - Calibrates for 10 seconds to establish a baseline, then switches to Real-Time Monitor mode.
     - View the live graph at `data/anomalies/live_monitor.png` (updates every 2 seconds).

2. **Simulate an Attack**
     - Open a second terminal (admin/sudo may be required for Scapy):
         ```bash
         python attacker.py --target_ip 127.0.0.1 --count 1000
         ```
     - Sends 1000 SYN packets to localhost.
     - Watch the detector terminal for messages like `Anomalies detected: [...]`.
     - The live graph should show a spike in packet volume.
