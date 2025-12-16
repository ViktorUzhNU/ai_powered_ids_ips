import pandas as pd
import time
import os
import random
from datetime import datetime

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "captured_packets.csv")

# Headers
COLUMNS = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packet_length']

def init_file():
    if not os.path.exists(DATA_PATH):
        os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
        pd.DataFrame(columns=COLUMNS).to_csv(DATA_PATH, index=False)
        print("Created new file with headers.")

def get_current_time_str():
    return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

def inject_packet(src_ip, dst_ip, src_port, dst_port, proto, length, label):
    data = {
        'timestamp': [get_current_time_str()],
        'src_ip': [src_ip],
        'dst_ip': [dst_ip],
        'src_port': [src_port],
        'dst_port': [dst_port],
        'protocol': [proto],
        'packet_length': [length]
    }
    
    df = pd.DataFrame(data, columns=COLUMNS)
    df.to_csv(DATA_PATH, mode='a', header=False, index=False)
    print(f"Sent [{label}]: {proto} Port:{dst_port} Len:{length} | IP: {src_ip}")

if __name__ == "__main__":
    print(f"Injecting HIGH-CONFIDENCE MALICIOUS TRAFFIC into: {DATA_PATH}")
    print("Generating 3 types of attacks...")
    print("Press Ctrl+C to stop.\n")
    
    init_file()

    try:
        while True:
            # --- 1. ATTACK: GIANT PACKETS (DoS Volumetric) ---
            # Kept as requested. High detection rate due to abnormal size.
            inject_packet(
                src_ip="66.66.66.66", 
                dst_ip="192.168.1.1", 
                src_port=random.randint(1024, 65000), 
                dst_port=80, 
                proto="TCP", 
                length=random.randint(2500, 5000), 
                label="ATTACK_GIANT_DOS"
            )
            time.sleep(0.3)

            # --- 2. ATTACK: WEB BRUTE FORCE ---
            # Kept as requested. Matches Thursday-WebAttacks dataset.
            inject_packet(
                src_ip="10.10.10.10", 
                dst_ip="192.168.1.1", 
                src_port=random.randint(1024, 65000), 
                dst_port=80, 
                proto="TCP", 
                length=random.randint(300, 800), 
                label="ATTACK_WEB_BRUTE"
            )
            time.sleep(0.3)

            # --- 3. ATTACK: LDAP DrDoS (NEW & HIGH CONFIDENCE) ---
            # Training file: DrDoS_LDAP.csv
            # Why this works: The model was explicitly trained on LDAP UDP floods.
            # Using standard LDAP port 389 and typical reflection packet sizes.
            inject_packet(
                src_ip="77.77.77.77",       # New Attacker IP
                dst_ip="192.168.1.1", 
                src_port=random.randint(1024, 65000), 
                dst_port=389,               # LDAP Port (Key feature for model)
                proto="UDP", 
                length=random.choice([1400, 1450, 1500]), # Fragmentation size typical in DrDoS
                label="ATTACK_LDAP_FLOOD"
            )
            time.sleep(0.3)

    except KeyboardInterrupt:
        print("\nStopped.")