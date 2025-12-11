# src/filtering/ip_filter.py
from collections import defaultdict
from src.utils.detection_log import log_detection

DEFAULT_THRESHOLD_RATE = 100
blacklist = set()
ip_packet_counts = defaultdict(int)

def check_and_filter_ip(src_ip, packet_count=None, threshold=DEFAULT_THRESHOLD_RATE):
    """
    Checks if an IP exceeds the threshold.
    If packet_count is provided, uses that. Otherwise increments internal counter.
    """
    global ip_packet_counts
    
    if packet_count is not None:
        current_count = packet_count
        ip_packet_counts[src_ip] = packet_count # Update internal state if needed
    else:
        ip_packet_counts[src_ip] += 1
        current_count = ip_packet_counts[src_ip]

    if current_count > threshold:
        if src_ip not in blacklist:
            blacklist.add(src_ip)
            log_detection(src_ip, current_count)
            print(f"IP {src_ip} blacklisted (Count: {current_count} > Threshold: {threshold})")
            return True
    return False

def reset_counts():
    """Resets the packet counts, useful for window-based monitoring."""
    global ip_packet_counts
    ip_packet_counts.clear()
