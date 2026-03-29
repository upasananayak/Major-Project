# #!/usr/bin/env python3
# """
# Measure storage, communication, and blockchain overhead.

# Outputs CSV for IEEE Transactions evaluation.
# """

# import os
# import sys
# import json
# import csv
# import argparse
# from pathlib import Path

# # ----------------------------------------------------------------------
# # Project root
# # ----------------------------------------------------------------------
# ROOT_DIR = Path(__file__).resolve().parent.parent
# if str(ROOT_DIR) not in sys.path:
#     sys.path.insert(0, str(ROOT_DIR))

# # ----------------------------------------------------------------------
# # JSON paths
# # ----------------------------------------------------------------------
# IOT_DEC_FN = ROOT_DIR / "iot_to_cloud_dec.json"
# IOT_VER_DEC_FN = ROOT_DIR / "iot_to_verifier_dec.json"
# CHAL_FN = ROOT_DIR / "challenge.json"
# CLOUD_PROOF_FN = ROOT_DIR / "cloud_to_verifier_dec.json"

# # Blockchain tx receipts
# BC_REGISTER_TX = ROOT_DIR / "blockchain_tx_register.json"
# BC_UPDATE_TX = ROOT_DIR / "blockchain_tx_update.json"
# BC_VERIFY_TX = ROOT_DIR / "blockchain_tx_verify.json"

# OUT_CSV = Path(__file__).resolve().parent / "overhead_results_blockchain.csv"


# # ----------------------------------------------------------------------
# # Helpers
# # ----------------------------------------------------------------------
# def file_bytes(path):
#     try:
#         return os.path.getsize(path)
#     except Exception:
#         return 0


# def json_bytes(obj):
#     try:
#         return len(json.dumps(obj).encode())
#     except Exception:
#         return 0


# def load_json(path):
#     try:
#         with open(path, "r") as f:
#             return json.load(f)
#     except Exception:
#         return None


# def load_tx_cost(path):
#     """
#     Returns (gasUsed, inputBytes)
#     """
#     tx = load_json(path)
#     if not tx:
#         return 0, 0
#     return tx.get("gasUsed", 0), tx.get("inputBytes", 0)


# # ----------------------------------------------------------------------
# # Main overhead computation
# # ----------------------------------------------------------------------
# def compute_overhead(file_size_bytes):

#     # Load protocol objects
#     iot_obj = load_json(IOT_DEC_FN)
#     ver_obj = load_json(IOT_VER_DEC_FN)
#     chal_obj = load_json(CHAL_FN)
#     cloud_obj = load_json(CLOUD_PROOF_FN)

#     # -------------------------
#     # STORAGE OVERHEAD
#     # -------------------------
#     commitments_bytes = json_bytes(ver_obj.get("commitments", [])) if ver_obj else 0

#     # Blockchain on-chain storage (per version)
#     # root (32) + commitment (32) + version (32) + status (1 padded)
#     blockchain_storage_bytes = 32 + 32 + 32 + 32

#     storage_overhead_bytes = commitments_bytes + blockchain_storage_bytes

#     # -------------------------
#     # COMMUNICATION OVERHEAD
#     # -------------------------
#     iot_payload_bytes = file_bytes(IOT_DEC_FN)
#     challenge_bytes = file_bytes(CHAL_FN)
#     cloud_payload_bytes = file_bytes(CLOUD_PROOF_FN)

#     # Blockchain calldata
#     reg_gas, reg_bytes = load_tx_cost(BC_REGISTER_TX)
#     upd_gas, upd_bytes = load_tx_cost(BC_UPDATE_TX)
#     ver_gas, ver_bytes = load_tx_cost(BC_VERIFY_TX)

#     blockchain_comm_bytes = reg_bytes + upd_bytes + ver_bytes

#     communication_overhead_bytes = (
#         iot_payload_bytes +
#         challenge_bytes +
#         cloud_payload_bytes +
#         blockchain_comm_bytes
#     )

#     # -------------------------
#     # BLOCKCHAIN EXECUTION COST
#     # -------------------------
#     total_gas_used = reg_gas + upd_gas + ver_gas

#     # -------------------------
#     # TOTAL
#     # -------------------------
#     combined_overhead_bytes = storage_overhead_bytes + communication_overhead_bytes

#     return {
#         "file_size_bytes": file_size_bytes,

#         # Storage
#         "commitments_storage_bytes": commitments_bytes,
#         "blockchain_storage_bytes": blockchain_storage_bytes,
#         "total_storage_overhead_bytes": storage_overhead_bytes,

#         # Communication
#         "iot_comm_bytes": iot_payload_bytes,
#         "challenge_comm_bytes": challenge_bytes,
#         "cloud_comm_bytes": cloud_payload_bytes,
#         "blockchain_comm_bytes": blockchain_comm_bytes,
#         "total_comm_overhead_bytes": communication_overhead_bytes,

#         # Blockchain cost
#         "blockchain_gas_used": total_gas_used,

#         # Combined
#         "combined_overhead_bytes": combined_overhead_bytes,
#         "combined_overhead_pct": (combined_overhead_bytes / max(1, file_size_bytes)) * 100
#     }


# # ----------------------------------------------------------------------
# # Entry
# # ----------------------------------------------------------------------
# def main():
#     parser = argparse.ArgumentParser()
#     parser.add_argument(
#         "--file-sizes", nargs="+", type=int,
#         default=[1024, 10*1024, 50*1024, 100*1024, 200*1024, 500*1024]
#     )
#     parser.add_argument("--out", default=str(OUT_CSV))
#     args = parser.parse_args()

#     rows = []
#     for fs in args.file_sizes:
#         print(f"Computing blockchain overhead for file size {fs} bytes")
#         rows.append(compute_overhead(fs))

#     if not rows:
#         print("No data.")
#         return

#     with open(args.out, "w", newline="") as f:
#         writer = csv.DictWriter(f, fieldnames=rows[0].keys())
#         writer.writeheader()
#         writer.writerows(rows)

#     print(f" Blockchain overhead results saved to {args.out}")


# if __name__ == "__main__":
#     main()

##========================

#!/usr/bin/env python3
# import os
# import sys
# import json
# import csv
# import random
# import string
# import subprocess
# import time
# from pathlib import Path

# # --- PATHS ---
# ROOT_DIR = Path(__file__).resolve().parent
# sys.path.append(str(ROOT_DIR))

# # Result files produced by the protocol
# IOT_CLOUD_ENC = ROOT_DIR / "iot_to_cloud.enc.json"
# IOT_VERIFIER_ENC = ROOT_DIR / "iot_to_verifier.enc.json"
# CHALLENGE_JSON = ROOT_DIR / "challenge.json"
# CLOUD_PROOF_ENC = ROOT_DIR / "cloud_to_verifier.enc.json"
# OUT_CSV = ROOT_DIR / "overhead_results_blockchain.csv"

# # --- CONFIGURATION ---
# TEST_FILE_SIZES = [16384,32768, 65536, 131072, 262144, 524288] # 1KB, 10KB, 50KB, 100KB
# CHALLENGES = [1, 5, 10, 20, 50, 100, 200, 300, 600] 

# # --- HELPERS ---
# def get_file_size(path):
#     return os.path.getsize(path) if os.path.exists(path) else 0

# def generate_dummy_file(filename, size):
#     data = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
#     with open(filename, "w") as f:
#         f.write(data)

# def cleanup():
#     # Remove temporary protocol files to ensure fresh measurements
#     to_remove = [IOT_CLOUD_ENC, IOT_VERIFIER_ENC, CHALLENGE_JSON, CLOUD_PROOF_ENC, "test_file.txt"]
#     for f in to_remove:
#         if os.path.exists(f): os.remove(f)

# # --- ANALYSIS LOGIC ---
# def run_analysis():
#     results = []
    
#     for size in TEST_FILE_SIZES:
#         test_file = "test_file.txt"
#         generate_dummy_file(test_file, size)
        
#         for c in CHALLENGES:
#             print(f"Analyzing Size: {size} bytes, Challenge: {c}")
#             cleanup()
#             generate_dummy_file(test_file, size)

#             try:
#                 # 1. Run IoT Upload (Stage 1)
#                 # We pipe the filename to scriptone.py
#                 subprocess.run([sys.executable, "scriptone.py"], input=f"{test_file}\n", text=True, capture_output=True)
                
#                 # 2. Run Verifier & Cloud (Stage 2)
#                 # We pipe the challenge size 'c' to scripttwo.py
#                 subprocess.run([sys.executable, "scripttwo.py"], input=f"{c}\n", text=True, capture_output=True)

#                 # --- MEASURE COMMUNICATION ---
#                 # Size of encrypted payloads sent over the network
#                 comm_iot_cloud = get_file_size(IOT_CLOUD_ENC)
#                 comm_iot_verifier = get_file_size(IOT_VERIFIER_ENC)
#                 comm_challenge = get_file_size(CHALLENGE_JSON)
#                 comm_proof = get_file_size(CLOUD_PROOF_ENC)

#                 # --- MEASURE STORAGE ---
#                 # On-chain storage overhead: 4 state variables (root, comm, version, status) 
#                 # Each typically 32 bytes in Solidity.
#                 blockchain_storage_bytes = 32 * 4 
                
#                 # Load commitments to see how much metadata IoT/Verifier stores
#                 # This assumes scripttwo.py or verifier.py has decrypted the payload
#                 commitments_bytes = 0
#                 if os.path.exists("iot_to_verifier_dec.json"):
#                     with open("iot_to_verifier_dec.json", "r") as f:
#                         data = json.load(f)
#                         commitments_bytes = len(json.dumps(data.get("commitments", [])).encode())

#                 total_comm = comm_iot_cloud + comm_iot_verifier + comm_challenge + comm_proof
#                 total_storage = blockchain_storage_bytes + commitments_bytes

#                 results.append({
#                     "file_size": size,
#                     "challenge_c": c,
#                     "iot_to_cloud_bytes": comm_iot_cloud,
#                     "iot_to_verifier_bytes": comm_iot_verifier,
#                     "challenge_bytes": comm_challenge,
#                     "proof_bytes": comm_proof,
#                     "total_communication": total_comm,
#                     "blockchain_storage": blockchain_storage_bytes,
#                     "metadata_storage": commitments_bytes,
#                     "total_storage_overhead": total_storage
#                 })

#             except Exception as e:
#                 print(f"Error processing size {size} c {c}: {e}")

#     # Write Results
#     if results:
#         with open(OUT_CSV, 'w', newline='') as f:
#             writer = csv.DictWriter(f, fieldnames=results[0].keys())
#             writer.writeheader()
#             writer.writerows(results)
#         print(f"\nOverhead results saved to {OUT_CSV}")

# if __name__ == "__main__":
#     run_analysis()

##========================


#!/usr/bin/env python3
import os
import sys
import json
import csv
import random
import string
import subprocess
from pathlib import Path

# --- PATHS ---
ROOT_DIR = Path(__file__).resolve().parent
sys.path.append(str(ROOT_DIR))

# Result files produced by the protocol
IOT_CLOUD_ENC = ROOT_DIR / "iot_to_cloud.enc.json"
IOT_VERIFIER_ENC = ROOT_DIR / "iot_to_verifier.enc.json"
CHALLENGE_JSON = ROOT_DIR / "challenge.json"
CLOUD_PROOF_ENC = ROOT_DIR / "cloud_to_verifier.enc.json"
# Assume this file contains the decrypted data stored on the cloud
IOT_CLOUD_DEC = ROOT_DIR / "iot_to_cloud_dec.json" 
OUT_CSV = ROOT_DIR / "overhead_results_blockchain.csv"

# --- CONFIGURATION ---
# TEST_FILE_SIZES = [16384, 32768, 65536, 131072, 262144, 524288]
TEST_FILE_SIZES = [16384]

CHALLENGES = [1, 5, 10, 20, 50, 100, 200, 300, 600]

# --- HELPERS ---
def get_file_size(path):
    return os.path.getsize(path) if os.path.exists(path) else 0

def generate_dummy_file(filename, size):
    data = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
    with open(filename, "w") as f:
        f.write(data)

def cleanup():
    to_remove = [IOT_CLOUD_ENC, IOT_VERIFIER_ENC, CHALLENGE_JSON, 
                 CLOUD_PROOF_ENC, IOT_CLOUD_DEC, "test_file.txt"]
    for f in to_remove:
        if os.path.exists(f): 
            try: os.remove(f)
            except: pass

# --- ANALYSIS LOGIC ---
def run_analysis():
    results = []
    
    print(f"\n{'='*120}")
    print(f" BLOCKCHAIN OVERHEAD ANALYSIS")
    print(f"{'='*120}\n")

    for size in TEST_FILE_SIZES:
        test_file = "test_file.txt"
        
        for c in CHALLENGES:
            print(f"Processing -> Size: {size} bytes | Challenge Count: {c}")
            cleanup()
            generate_dummy_file(test_file, size)

            try:
                # 1. Run IoT Upload (Stage 1)
                subprocess.run([sys.executable, "scriptone.py"], input=f"{test_file}\n", text=True, capture_output=True)
                
                # 2. Run Verifier & Cloud (Stage 2)
                subprocess.run([sys.executable, "scripttwo.py"], input=f"{c}\n", text=True, capture_output=True)

                # --- METRIC MAPPING ---
                comm_iot_cloud = get_file_size(IOT_CLOUD_ENC)
                comm_iot_verifier = get_file_size(IOT_VERIFIER_ENC)
                comm_verifier_cloud = get_file_size(CHALLENGE_JSON)
                comm_cloud_verifier = get_file_size(CLOUD_PROOF_ENC)
                
                # Storage on Cloud (Decrypted/Processed file size)
                storage_cloud_total = get_file_size(IOT_CLOUD_DEC)
                expansion_ratio = round(storage_cloud_total / size, 4) if size > 0 else 0

                # Blockchain: Store Payload (Root, Comm, Ver, Status - approx 32 bytes each)
                bc_store_payload = 32 * 4 
                
                # Blockchain: Verify Payload (Proof data sent for on-chain verification)
                # This is typically the size of the proof sent from Cloud to Verifier
                bc_verify_payload = comm_cloud_verifier 

                # Create row with EXACT requested headers
                results.append({
                    "Original Size": size,
                    "Challenge Count": c,
                    "Comm: IoT->Cloud": comm_iot_cloud,
                    "Comm: IoT->Verifier": comm_iot_verifier,
                    "Comm: Verifier->Cloud": comm_verifier_cloud,
                    "Comm: Cloud->Verifier": comm_cloud_verifier,
                    "Blockchain: Store Payload": bc_store_payload,
                    "Blockchain: Verify Payload": bc_verify_payload,
                    "Storage: Cloud Total": storage_cloud_total,
                    "Storage Expansion Ratio": expansion_ratio
                })

            except Exception as e:
                print(f"Error processing size {size} c {c}: {e}")

    # Write Results to CSV
    if results:
        with open(OUT_CSV, 'w', newline='') as f:
            # Fieldnames are taken directly from the keys of the first dictionary
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        print(f"\nSuccess! Results saved to {OUT_CSV}")

if __name__ == "__main__":
    run_analysis()