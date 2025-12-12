# src/capture/packet_sniffer.py
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from datetime import datetime
import threading
import time

# Global storage for captured packets
traffic_data = pd.DataFrame(columns=['timestamp', 'protocol', 'src_ip', 'dst_ip', 'pkt_size', 'flags'])
DATA_LOCK = threading.Lock()

def packet_callback(packet):
    global traffic_data
    if packet.haslayer(IP):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        protocol = packet[IP].proto
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_size = len(packet)

        # Capture TCP flags if it's a TCP packet
        flags = None
        if packet.haslayer(TCP):
            flags = packet[TCP].flags
        elif packet.haslayer(UDP):
            flags = "UDP"

        # Store packet data
        with DATA_LOCK:
            traffic_data.loc[len(traffic_data)] = [timestamp, protocol, src_ip, dst_ip, pkt_size, flags]
        
        # print(f"[{timestamp}] Size: {pkt_size} Src: {src_ip}") # Reduced verbosity

def start_sniffing_thread(interface=None):
    """
    Starts packet sniffing in a separate daemon thread.
    - interface: Network interface to sniff (e.g., 'eth0', 'lo', or None for default).
    """
    def sniff_job():
        # store=0 prevents Scapy from keeping all packets in memory
        try:
            if interface:
                sniff(prn=packet_callback, store=0, iface=interface)
            else:
                sniff(prn=packet_callback, store=0)
        except Exception as e:
            print(f"Error in sniffing thread: {e}")

    # Create and start the thread
    sniffer_thread = threading.Thread(target=sniff_job)
    sniffer_thread.daemon = True
    sniffer_thread.start()

# Deprecated blocking function, keeping for compatibility if needed or changing behavior
def start_sniffing(count=0, timeout=None):
    """
    Blocking sniff (Legacy). 
    """
    sniff(prn=packet_callback, count=count, timeout=timeout, store=0)

def get_and_clear_captured_data():
    """
    Returns the accumulated traffic data and clears the buffer.
    """
    global traffic_data
    with DATA_LOCK:
        data = traffic_data.copy()
        # Reset dataframe
        traffic_data = pd.DataFrame(columns=['timestamp', 'protocol', 'src_ip', 'dst_ip', 'pkt_size', 'flags'])
    return data

def save_captured_data(file_path="data/raw/captured_traffic.csv"):
    with DATA_LOCK:
        traffic_data.to_csv(file_path, index=False)

def run_sniffer(count=100, stats_interval=5):
    # Standalone run using the blocking method for simplicity
    start_sniffing(count=count)
    save_captured_data()

if __name__ == "__main__":
    run_sniffer(count=100)
