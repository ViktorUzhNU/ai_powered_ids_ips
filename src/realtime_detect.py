

import os
import pandas as pd
import joblib
import subprocess
import sys
from time import sleep, time

# Import Threat Intel
# Ensure threat_intel.py is in the same folder or properly referenced
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
try:
    from threat_intel import check_ip_abuse
except ImportError:
    print("WARNING: 'threat_intel.py' not found. AbuseIPDB checks will be skipped.")
    check_ip_abuse = None

# Config
ALERT_THRESHOLD = 0.60  # Show alert if model is 65% sure
ABUSE_SCORE_THRESHOLD = 50 # Block IP if AbuseIPDB score >= 50
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY') # Make sure to set this in your environment or paste key here

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "..", "data", "captured_packets.csv")
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "rf_realistic_cicids.joblib")
ENCODER_PATH = os.path.join(BASE_DIR, "..", "models", "proto_encoder_realistic.joblib")
LOG_PATH = os.path.join(BASE_DIR, "..", "data", "alerts.log")

# Load model and encoder
print("Loading AI models...")
try:
    model = joblib.load(MODEL_PATH)
    proto_encoder = joblib.load(ENCODER_PATH)
except FileNotFoundError as e:
    print(f"Error loading models: {e}")
    exit()

# Protocol mapping
PROTO_MAP = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp'}
blocked_ips = set()

# --- ADDED: Block IP Function ---
def block_ip(ip):
    if ip in blocked_ips:
        return
    
    # Don't block private IPs (Local Network)
    if ip.startswith(('192.168.', '10.', '127.')):
        print(f"Skipping block for local IP: {ip}")
        return

    try:
        cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip} enable=yes'
        subprocess.run(cmd, shell=True, check=True)
        blocked_ips.add(ip)
        
        msg = f"[AUTO-BLOCKED] IP {ip} was added to Windows Firewall blacklist."
        print(msg)
        with open(LOG_PATH, 'a') as f:
            f.write(msg + "\n")
            
    except Exception as e:
        err_msg = f"Failed to block IP {ip}: {e}"
        print(err_msg)
        with open(LOG_PATH, 'a') as f:
            f.write(err_msg + "\n")

print(f"Real-time IDS started — Threshold: {ALERT_THRESHOLD * 100}%")
if ABUSEIPDB_API_KEY:
    print("Threat Intelligence: ACTIVE (AbuseIPDB)")
else:
    print("Threat Intelligence: INACTIVE (No API Key found)")

print("Waiting for traffic...\n")

last_seen = 0
stats = {"total": 0, "suspicious": 0, "start_time": time()}

while True:
    if not os.path.exists(DATA_PATH):
        sleep(1)
        continue

    try:
        # Robust CSV reading
        df = pd.read_csv(DATA_PATH, engine='python', on_bad_lines='skip')
    except Exception:
        sleep(0.1)
        continue

    if len(df) <= last_seen:
        sleep(0.5)
        continue

    new_packets = df.iloc[last_seen:].copy()
    last_seen = len(df)
    stats["total"] += len(new_packets)

    # Filter out multicast/local
    #try:
        #mask = ~(
            #new_packets['dst_ip'].astype(str).str.startswith(('224.', '239.', '169.254')) |
            #new_packets['src_ip'].astype(str).str.startswith(('224.', '239.', '169.254')) |
            #(new_packets['src_ip'] == new_packets['dst_ip']) |
            #((new_packets['protocol'] == 'TCP') & (new_packets['source_bytes'] == 54))
        #)
        #new_packets = new_packets[mask].reset_index(drop=True)

        # WHITELIST
        #whitelist_prefixes = ('20.', '52.', '13.', '142.250', '172.217') 
        #is_whitelisted = new_packets['dst_ip'].astype(str).str.startswith(whitelist_prefixes)
        #new_packets = new_packets[~is_whitelisted]
        
        
    #except Exception:
        #continue

    if len(new_packets) == 0:
        continue

    # Prepare features
    features = []
    for _, row in new_packets.iterrows():
        try:
            proto = PROTO_MAP.get(str(row['protocol']).upper(), 'tcp')
            if proto in proto_encoder.classes_:
                proto_enc = proto_encoder.transform([proto])[0]
            else:
                proto_enc = 0
            src_bytes = int(row['packet_length']) if pd.notnull(row['packet_length']) else 0
            features.append([proto_enc, src_bytes, 0])
        except:
            continue

    if len(features) == 0:
        continue

    X = pd.DataFrame(features, columns=['protocol_type', 'src_bytes', 'dst_bytes'])
    
    try:
        probabilities = model.predict_proba(X)
    except:
        continue

    for i, probs in enumerate(probabilities):
        suspicion_confidence = probs[1]

        if suspicion_confidence >= ALERT_THRESHOLD:
            stats["suspicious"] += 1
            pkt = new_packets.iloc[i]
            src_ip = pkt['src_ip']
            
            try:
                src_port = int(pkt['src_port'])
            except:
                src_port = "?"
            try:
                dst_port = int(pkt['dst_port'])
            except:
                dst_port = "?"

            alert = (f"[SUSPICIOUS #{stats['suspicious']}] "
                     f"Confidence: {suspicion_confidence*100:.1f}% | "
                     f"{src_ip}:{src_port} -> {pkt['dst_ip']}:{dst_port} | "
                     f"{pkt['protocol']} | len={int(pkt['packet_length'])}")

            print(alert)
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(alert + "\n")
            
    # THREAT INTELLIGENCE CHECK
            if ABUSEIPDB_API_KEY and check_ip_abuse:
                # Check if we should ignore this IP like local IP
                if not src_ip.startswith(('192.168.', '10.', '127.')):
                    print(f"   >>> Checking reputation for {src_ip}...")
                    abuse_result = check_ip_abuse(src_ip, ABUSEIPDB_API_KEY)
                    
                    if abuse_result:
                        score = abuse_result.get('abuseConfidenceScore', 0)
                        country = abuse_result.get('countryCode', 'Unknown')
                        
                        # Add ipAddress key because dashboard expects it
                        abuse_result['ipAddress'] = abuse_result['ip']

                        # Log the full dictionary so the dashboard can parse it
                        intel_log = f"AbuseIPDB: {abuse_result}"
                        
                        with open(LOG_PATH, "a", encoding="utf-8") as f:
                            f.write(intel_log + "\n")

                        print(f"   >>> AbuseIPDB Score: {score}/100 ({country})")
                        
                        # AUTO BLOCK if dangerous
                        if score >= ABUSE_SCORE_THRESHOLD:
                            block_ip(src_ip)

    if time() - stats["start_time"] >= 30:
        rate = (stats["suspicious"] / stats["total"] * 100) if stats["total"] > 0 else 0
        print(f"\n[SUMMARY] Packets: {stats['total']:,} | Suspicious Events: {stats['suspicious']} ({rate:.3f}%)\n")
        stats["start_time"] = time()

    sleep(0.5)