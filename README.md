# AI-Powered IDS/IPS


## Architecture
```
+-------------------+      +-------------------+      +-------------------+
|  Packet Sniffer   | ---> |  ML Classifier    | ---> |  Alert/Block/Log  |
+-------------------+      +-------------------+      +-------------------+
        |                        |                           |
        v                        v                           v
   [captured_packets.csv]   [rf_realistic_cicids.joblib]         [alerts.log]
        |                        |                           |
        +------------------------+---------------------------+
                                 |
                                 v
                        [Streamlit Dashboard]
```



## Project Structure

/ai_powered_ids_ips
│
├── /data                        # Directory for storing data
│   ├── captured_packets.csv     # Captured packets buffer (runtime)
│   ├── alerts.log               # Log file for detected threats
│   ├── GeoLite2-City.mmdb       # Database for IP geolocation
│   └── [CSV files]              # CIC-IDS-2017/2019 files for training
│
├── /models                      # Directory for binary model files
│   ├── rf_realistic_cicids.joblib      # Trained Random Forest model
│   └── proto_encoder_realistic.joblib  # Protocol encoder
│
├── /src                         # Source code of the system core
│   ├── download_datasets.py     # Module for downloading training data
│   ├── train_model.py           # Script for model training and evaluation
│   ├── sniffer.py               # Traffic sniffing module
│   ├── realtime_detect.py       # Main threat detection module
│   └── threat_intel.py          # AbuseIPDB integration module
│
├── /dashboard                   # GUI components
│   └── app.py                   # Main Streamlit web application file
│
├── requirements.txt             # List of dependencies and libraries
├── .gitignore                   # Rules for excluding files from Git
└── README.md                    # User documentation
---

## Quickstart (Local)

### 1. Clone the Repository
```sh
git clone <https://github.com/ViktorUzhNU/ai_powered_ids_ips>
cd ai_powered_ids_ips
```

### 2. Set Up Python Environment
```sh
python -m venv venv
venv\Scripts\activate  # On Windows
# or
source venv/bin/activate  # On Linux/Mac
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Prepare Dataset & Train Model
```sh
python src/download_datasets.py      # Download and preprocess CIC-IDS2017 and CIC-DDOS2019
python src/train_model.py       # Train and save the ML model
```

### 4. Start Packet Capture
```sh
python src/sniffer.py           # Run in a separate terminal
```

### 5. (Optional) Set AbuseIPDB API Key
Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/).
```sh
$env:ABUSEIPDB_API_KEY="your_api_key_here"  # Windows
export ABUSEIPDB_API_KEY="your_api_key_here"  # Linux/Mac
```

### 6. Run Real-Time Detection
```sh
python src/realtime_detect.py   # Run in a separate terminal
```

### 7. Launch the Dashboard
```sh
streamlit run dashboard/app.py
```
Visit [http://localhost:8501](http://localhost:8501) in your browser.

---

