# src/visualize.py
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter
import os

def visualize_data(file_path="data/processed/anomaly_detected.csv", 
                  save_path="data/anomalies/live_monitor.png", 
                  plot_type='line',
                  data_frame=None):
    """
    Visualizes traffic data.
    If data_frame is provided, uses it directly. Otherwise, loads from file_path.
    Saves plot to save_path.
    """
    try:
        # Load data if not provided
        if data_frame is not None:
             data = data_frame.copy()
        elif os.path.exists(file_path):
             data = pd.read_csv(file_path)
        else:
             print(f"No data to visualize at {file_path}")
             return

        if 'timestamp' in data.columns:
            data['timestamp'] = pd.to_datetime(data['timestamp'])
        else:
             data['timestamp'] = pd.to_datetime('now')

        # Create figure and axis
        fig, ax = plt.subplots(figsize=(10, 5))

        # Check for aggregated history data (packet_count)
        if 'packet_count' in data.columns:
            ax.plot(data['timestamp'], data['packet_count'], label="Packet Volume", color='blue', marker='o')
            ax.set_title("Live Traffic Volume (Rolling Window)", fontsize=14)
            ax.set_ylabel("Packets per Window", fontsize=10)
            
            # Print summary
            last_count = data.iloc[-1]['packet_count'] if not data.empty else 0
            print(f"\n[Monitor] Last Window Volume: {last_count} packets")

        elif 'pkt_size' in data.columns:
             # Fallback to per-packet size plot
             ax.plot(data['timestamp'], data['pkt_size'], label="Packet Size", color='green', alpha=0.6)
             ax.set_title("Live Traffic Monitor (Raw Packets)", fontsize=14)
             ax.set_ylabel("Packet Size", fontsize=10)

        # Set common labels
        ax.set_xlabel("Time", fontsize=10)
        ax.legend()

        # Format x-axis
        if not data.empty:
             ax.xaxis.set_major_formatter(DateFormatter("%H:%M:%S"))
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        # Save the plot
        plt.savefig(save_path)
        plt.close(fig) # Close the figure to free memory

    except Exception as e:
        print(f"Visualization error: {e}")

if __name__ == "__main__":
    visualize_data()
