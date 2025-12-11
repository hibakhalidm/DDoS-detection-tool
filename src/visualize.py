# src/visualize.py
import pandas as pd
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
             # Create a dummy timestamp if missing for visualization
             data['timestamp'] = pd.date_range(start='2021-01-01', periods=len(data), freq='S')

        # Create aggregate stats for text summary
        print("\n--- Live Monitor Summary ---")
        if 'src_ip' in data.columns:
             top_ips = data['src_ip'].value_counts().head(5)
             print("Top 5 Source IPs by Packet Volume:")
             print(top_ips)
        
        # Create figure and axis
        fig, ax = plt.subplots(figsize=(10, 5))

        # We want to plot packet size over time, or just packet counts per IP?
        # The prompt says "save the plot... e.g. Top 5 IPs by Packet Rate".
        # Let's adjust the plot to be more useful for DDoS monitoring.
        # Maybe a time series of packet counts?
        
        # For now, let's keep the time series of packet size and highlight anomalies if we have that info.
        # But since we are moving to aggregation by IP, the 'anomaly' column might be on the IP level, 
        # or we might have per-packet anomalies (passed from main.py if we merge it back).
        
        # If we have 'is_syn' or 'pkt_size', plot those.
        if 'pkt_size' in data.columns:
             ax.plot(data['timestamp'], data['pkt_size'], label="Packet Size", color='blue', alpha=0.6)
        
        # Set title and labels
        ax.set_xlabel("Time", fontsize=10)
        ax.set_ylabel("Packet Size / Volume", fontsize=10)
        ax.set_title("Live Traffic Monitor", fontsize=14)
        ax.legend()

        # Format x-axis
        if not data['timestamp'].empty:
             ax.xaxis.set_major_formatter(DateFormatter("%H:%M:%S"))
        plt.xticks(rotation=45)
        plt.tight_layout()

        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        # Save the plot
        plt.savefig(save_path)
        print(f"Plot saved to {save_path}")
        plt.close(fig) # Close the figure to free memory

    except Exception as e:
        print(f"Visualization error: {e}")

if __name__ == "__main__":
    visualize_data()
