from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def packet_callback(packet):
    print("="*60)
    print(f" Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f" Source IP: {ip_layer.src}")
        print(f" Destination IP: {ip_layer.dst}")
        
        # Identify Protocol
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "Other"
        print(f" Protocol: {proto}")
        
        # Check for payload
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors='ignore')
                print(f" Payload:\n{payload}")
            except Exception as e:
                print(" Payload: [Could not decode]")

    else:
        print(" Non-IP packet captured.")

print("🔍 Starting Packet Sniffer (Press CTRL+C to stop)...")
sniff(prn=packet_callback, store=False)
