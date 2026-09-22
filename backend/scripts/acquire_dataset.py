import os
import urllib.request
import zipfile
import json
import random
import shutil

DATASET_URL_APK = "https://huggingface.co/datasets/Xinzxr/MalEval/resolve/main/apk.zip"
DATASET_URL_BENIGN = "https://huggingface.co/datasets/Xinzxr/MalEval/resolve/main/info/benign_sample_info.json"
DATASET_URL_MALWARE = "https://huggingface.co/datasets/Xinzxr/MalEval/resolve/main/info/latest_sample_info.json"

RAW_DATA_DIR = "data/raw"
os.makedirs(RAW_DATA_DIR, exist_ok=True)

# 1. Download metadata
print("Downloading metadata...")
urllib.request.urlretrieve(DATASET_URL_BENIGN, "benign_info.json")
urllib.request.urlretrieve(DATASET_URL_MALWARE, "malware_info.json")

with open("benign_info.json", "r") as f:
    benign_data = json.load(f)
with open("malware_info.json", "r") as f:
    malware_data = json.load(f)

# 2. Select 20 of each
random.seed(42) # For reproducibility
benign_hashes = list(benign_data.keys())
malware_hashes = list(malware_data.keys())

selected_benign = random.sample(benign_hashes, min(20, len(benign_hashes)))
selected_malware = random.sample(malware_hashes, min(20, len(malware_hashes)))

# 3. Download apk.zip
print("Downloading apk.zip (~800MB). This may take a minute...")
urllib.request.urlretrieve(DATASET_URL_APK, "apk.zip")

# 4. Extract selected files
print("Extracting 40 selected APKs...")
extracted_count = 0
with zipfile.ZipFile("apk.zip", 'r') as zip_ref:
    for file_info in zip_ref.infolist():
        # The zip contains files in directories, e.g., apk/benign/xxx.apk
        filename = os.path.basename(file_info.filename)
        if filename.endswith(".apk"):
            sha256 = filename[:-4]
            if sha256 in selected_benign or sha256 in selected_malware:
                # Extract to data/raw flat
                source = zip_ref.open(file_info)
                target_path = os.path.join(RAW_DATA_DIR, filename)
                with open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)
                extracted_count += 1

print(f"Extracted {extracted_count} APKs to {RAW_DATA_DIR}.")

# 5. Cleanup
os.remove("apk.zip")
os.remove("benign_info.json")
os.remove("malware_info.json")
print("Cleaned up temporary files.")
