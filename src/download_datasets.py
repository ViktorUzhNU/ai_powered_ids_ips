import os
import requests
import zipfile
import shutil

# --- CONFIGURATION ---
DATA_DIR = "data"

# Dataset 2017 Config
URL_2017 = "http://cicresearch.ca/CICDataset/CIC-IDS-2017/Dataset/CIC-IDS-2017/CSVs/MachineLearningCSV.zip"
TARGETS_2017 = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
]

# Dataset 2019 Config
URL_2019 = "http://cicresearch.ca/CICDataset/CICDDoS2019/Dataset/CSVs/CSV-01-12.zip"
TARGETS_2019 = [
    "DrDoS_DNS.csv",
    "DrDoS_LDAP.csv",
    "DrDoS_UDP.csv",
]

def download_and_extract(url, target_files, output_dir):
    # Ensure directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 1. Download the ZIP file
    zip_filename = url.split('/')[-1]
    zip_path = os.path.join(output_dir, zip_filename)

    print(f"--- Processing: {zip_filename} ---")

    if not os.path.exists(zip_path):
        print(f"Downloading from {url}...")
        # Stream download to avoid memory issues with large files
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(zip_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        print("Download complete.")
    else:
        print("ZIP file already exists. Skipping download.")

    # 2. Extract only specific files
    print("Extracting specific files...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        # Check every file inside the archive
        for member in zip_ref.namelist():
            file_name = os.path.basename(member)
            
            # If this file is in our target list
            if file_name in target_files:
                # Extract it to the output_dir (flattening the path)
                source = zip_ref.open(member)
                target_path = os.path.join(output_dir, file_name)
                
                with open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                print(f" -> Extracted: {file_name}")
    print("\n")

if __name__ == "__main__":
    # Run for 2017
    download_and_extract(URL_2017, TARGETS_2017, DATA_DIR)
    
    # Run for 2019
    download_and_extract(URL_2019, TARGETS_2019, DATA_DIR)

    print(f"Done! Check the '{DATA_DIR}' folder.")