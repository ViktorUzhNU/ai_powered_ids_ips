

import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from imblearn.under_sampling import RandomUnderSampler
import joblib


# 1. Configuration & Paths

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CIC_FOLDER = os.path.join(BASE_DIR, "..", "data")
MODEL_PATH = os.path.join(BASE_DIR, "..", "models", "rf_realistic_cicids.joblib")
ENCODER_PATH = os.path.join(BASE_DIR, "..", "models", "proto_encoder_realistic.joblib")

# List of CIC-IDS-2017-2019 files to use
FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "DrDoS_DNS.csv",
    "DrDoS_LDAP.csv",
    "DrDoS_UDP.csv",
]

MAX_ROWS_PER_FILE = 80_000   # Set the maximum read from the datasets


# 2. Load Data

print("Loading CIC-IDS-2017-2019 files...")
dfs = []

for f in FILES:
    path = os.path.join(CIC_FOLDER, f)
    if not os.path.exists(path):
        print(f"  [SKIP] {f} not found")
        continue

    # Load subset of rows for speed
    df = pd.read_csv(path, nrows=MAX_ROWS_PER_FILE, low_memory=False)
    df.columns = df.columns.str.strip()
    print(f"  Loaded {f}: {len(df):,} rows")
    dfs.append(df)

if not dfs:
    raise FileNotFoundError("No CSV files found! Check your paths.")

data = pd.concat(dfs, ignore_index=True)


# 3. Preprocessing & Cleaning

print("Preprocessing data...")
data.replace([np.inf, -np.inf], np.nan, inplace=True)
data.fillna(0, inplace=True)

# Convert Labels: 0 = Benign, 1 = Attack
data['Label'] = data['Label'].apply(lambda x: 0 if str(x).strip().upper() == 'BENIGN' else 1)

# Logic to handle missing 'Protocol' column (infer from ports/flags)
if 'Protocol' in data.columns:
    data['protocol_type_raw'] = data['Protocol']
else:
    data['protocol_type_raw'] = 'tcp' # default
    data.loc[data['SYN Flag Count'] > 0, 'protocol_type_raw'] = 'tcp'
    data.loc[data['Destination Port'] == 53, 'protocol_type_raw'] = 'udp'

# Standardize protocol names
data['protocol_type_raw'] = data['protocol_type_raw'].astype(str).str.lower()

# Initialize Encoder with known protocols
proto_encoder = LabelEncoder()
proto_encoder.fit(['tcp', 'udp', 'icmp']) 

# Encode protocols (safe transform)
data['protocol_type'] = data['protocol_type_raw'].apply(
    lambda x: proto_encoder.transform([x])[0] if x in proto_encoder.classes_ else proto_encoder.transform(['tcp'])[0]
)

# Extract real-time features
# We treat 'Total Length of Fwd Packets' as 'src_bytes'
data['src_bytes'] = pd.to_numeric(data['Total Length of Fwd Packets'], errors='coerce').fillna(0).astype(int)
data['dst_bytes'] = 0  # Not strictly needed for DoS detection, set to 0


# Select Feature Matrix (X) and Target Vector (y)
X = data[['protocol_type', 'src_bytes', 'dst_bytes']]
y = data['Label']


# 4. Balancing Classes
print("Balancing classes using RandomUnderSampler...")
rus = RandomUnderSampler(random_state=42)
X_bal, y_bal = rus.fit_resample(X, y)

# 5.  Data Augmentation (Fuzzing)
# We add synthetic noise to packet sizes to prevent the model 
# from memorizing specific numbers (overfitting).
print("Applying Data Augmentation (Fuzzing) to generalize detection...")

X_aug = X_bal.copy()
y_aug = y_bal.copy()

# Add +/- 10% random noise to src_bytes
noise = np.random.uniform(0.9, 1.1, size=len(X_aug))
X_aug['src_bytes'] = (X_aug['src_bytes'] * noise).astype(int)

# Combine original data with augmented data
X_final = pd.concat([X_bal, X_aug])
y_final = pd.concat([y_bal, y_aug])


# Hybrid Synthetic data: TCP & UDP (700-1514 bytes)

print("Adding hybrid synthetic benign UDP & TCP data (700-1514 bytes)...")
num_synthetic_per_proto = 30000  # Number of synthetic samples per protocol

# Get encoded values
udp_code = proto_encoder.transform(['udp'])[0]
tcp_code = proto_encoder.transform(['tcp'])[0]

# Generate TCP benign samples
tcp_protos = np.full(num_synthetic_per_proto, tcp_code)
tcp_bytes = np.random.randint(700, 1515, num_synthetic_per_proto)
tcp_dst = np.zeros(num_synthetic_per_proto)

# Generate UDP benign samples
udp_protos = np.full(num_synthetic_per_proto, udp_code)
udp_bytes = np.random.randint(650, 1515, num_synthetic_per_proto)
udp_dst = np.zeros(num_synthetic_per_proto)

# Combine arrays
combined_protos = np.concatenate([tcp_protos, udp_protos])
combined_bytes = np.concatenate([tcp_bytes, udp_bytes])
combined_dst = np.concatenate([tcp_dst, udp_dst])

synthetic_X = pd.DataFrame({
    'protocol_type': combined_protos,
    'src_bytes': combined_bytes,
    'dst_bytes': combined_dst
})
synthetic_y = pd.Series(np.zeros(len(synthetic_X)))  # Label as benign (0)

X_final = pd.concat([X_final, synthetic_X])
y_final = pd.concat([y_final, synthetic_y])

print(f"Final training set size: {len(X_final):,} records")


# 6. Train Robust Model
X_train, X_test, y_train, y_test = train_test_split(X_final, y_final, test_size=0.2, random_state=42)

print("Training Random Forest Classifier...")
rf = RandomForestClassifier(
    n_estimators=100,        
    max_depth=14,            # LIMIT DEPTH: Prevents memorization of exact values
    min_samples_leaf=50,     # MIN SAMPLES: Forces model to learn generalized rules
    n_jobs=-1,
    random_state=42,
    class_weight='balanced'
)
rf.fit(X_train, y_train)


# 7. Evaluation & Saving
y_pred = rf.predict(X_test)
print("\n=== Evaluation (Random Forest Model) ===")
print(classification_report(y_test, y_pred, target_names=["Benign", "Attack"]))

# Save artifacts
joblib.dump(rf, MODEL_PATH)
joblib.dump(proto_encoder, ENCODER_PATH)

print(f"\n[SUCCESS] Robust Model saved to: {MODEL_PATH}")
print(f"[SUCCESS] Encoder saved to: {ENCODER_PATH}")
print("Ready for real-time detection.")