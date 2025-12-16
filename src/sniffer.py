
import os
import pandas as pd
from datetime import datetime
import scapy.all as scapy

# Path to save captured packets
DATA_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "captured_packets.csv")

# Features we want to extract from each packet
FEATURE_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "packet_length"
]

# Create data directory if it doesn't exist
os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)


def extract_features(pkt):
    # Skip non-IP packets
    if not pkt.haslayer(scapy.IP):
        return None

    ip = pkt[scapy.IP]

    # Map protocol number to name
    proto_num = ip.proto
    proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, str(proto_num))

    # Try to get ports (only for TCP/UDP)
    src_port = dst_port = None
    if proto_name == "TCP" and pkt.haslayer(scapy.TCP):
        src_port = pkt[scapy.TCP].sport
        dst_port = pkt[scapy.TCP].dport
    elif proto_name == "UDP" and pkt.haslayer(scapy.UDP):
        src_port = pkt[scapy.UDP].sport
        dst_port = pkt[scapy.UDP].dport

    # Build feature dictionary
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto_name,
        "packet_length": len(pkt)
    }


def packet_handler(packet):
    # Extract features from current packet
    features = extract_features(packet)
    if not features:
        return  # ignore non-IP packets silently

    # Create DataFrame with one row
    row_df = pd.DataFrame([features])

    # Save to CSV: create file with header if new, append without header otherwise
    if not os.path.exists(DATA_FILE):
        row_df.to_csv(DATA_FILE, index=False, mode="w")
        print("Capture started. Saving packets to:")
        print(f"    {DATA_FILE}")
    else:
        row_df.to_csv(DATA_FILE, index=False, mode="a", header=False)

    # Show live info in console
    ts = features["timestamp"].split("T")[1][:8]
    print(f"[{ts}] {features['src_ip']} → {features['dst_ip']} | "
          f"{features['protocol']} | len={features['packet_length']}")


if __name__ == "__main__":
    print("Packet capture started. Press Ctrl+C to stop.\n")
    try:
        # Start sniffing on default interface
        scapy.sniff(prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\nCapture stopped by user. ")