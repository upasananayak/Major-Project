import os
import json
import random
import string
import csv
import sys
from contextlib import contextmanager

from iot_simulation import SimpleIoTDevice
from cloud_server import SimpleCloudServer
from generate_challenge import decrypt_iot_verifier_file 
import secrets
from utils import pseudo_random_permutation, pseudo_random_function

TEST_FILE_SIZES = [1024]
CHALLENGE_COUNTS_ARRAY = [1]  
OUTPUT_CSV = "overhead_results_varied.csv"

def get_file_size(filename):
    if os.path.exists(filename):
        return os.path.getsize(filename)
    return 0

def calculate_blockchain_store_payload(iot_device):
    return 200 + (len(iot_device.commitments) * 32) + (4 * 32)

def calculate_blockchain_verify_payload(cloud_server):
    total_bytes = 0
    total_bytes += 64
    c = len(cloud_server.challenge_set)
    total_bytes += (c * 32) + (c * 32)
    
    for chunk_id_str, path in cloud_server.aai_data.items():
        total_bytes += 32 # Leaf tag
        total_bytes += len(path) * 32 # Hashes
        total_bytes += len(path) * 32 # Metadata overhead (approx)
    return total_bytes

@contextmanager
def suppress_output():
    with open(os.devnull, "w") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:
            yield
        finally:
            sys.stdout = old_stdout

def cleanup_full():
    files = ["iot_to_cloud.enc.json", "iot_to_verifier.enc.json", 
             "challenge.json", "cloud_to_verifier.enc.json", 
             "iot_cache.json", "merkle_state.json", "iot_to_cloud_dec.json"]
    for f in files:
        if os.path.exists(f):
            try: os.remove(f)
            except: pass

def generate_dummy_file(filename, size):
    chars = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
    with open(filename, "w") as f:
        f.write(chars)


def run_overhead_analysis():
    results = []
    
    print(f"\n{'='*110}")
    print(f" COMMUNICATION & STORAGE OVERHEAD ANALYSIS (Varied Challenges)")
    print(f"{'='*110}\n")

    print(f"{'Size':<9} | {'Chal(c)':<7} | {'IoT->Cld':<9} | {'IoT->Ver':<9} | {'Cld->Ver':<9} | {'BC Store':<9} | {'BC Veri':<9} | {'Cld Stor':<9}")
    print(f"{'(Bytes)':<9} | {'(Count)':<7} | {'(Bytes)':<9} | {'(Bytes)':<9} | {'(Bytes)':<9} | {'(Bytes)':<9} | {'(Bytes)':<9} | {'(Bytes)':<9}")
    print("-" * 110)

    for size in TEST_FILE_SIZES:
        filename = f"overhead_test_{size}.txt"
        generate_dummy_file(filename, size)
        
        cleanup_full()
        
        try:
           
            with suppress_output():
                iot = SimpleIoTDevice()
                iot.run_complete_workflow(filename)
            
            comm_iot_cloud = get_file_size("iot_to_cloud.enc.json")
            comm_iot_verifier = get_file_size("iot_to_verifier.enc.json")
            bc_store_bytes = calculate_blockchain_store_payload(iot)
            storage_cloud_total = get_file_size("iot_to_cloud_dec.json")
            expansion = storage_cloud_total / size if size > 0 else 0

            for c_count in CHALLENGE_COUNTS_ARRAY:
                
                with suppress_output():
                    decrypt_iot_verifier_file()
                    with open("iot_to_verifier_dec.json", "r") as f:
                        data = json.load(f)
                        num_chunks = int(data.get("num_chunks"))
                    
                    with open("zk_params.json", "r") as f:
                        zk = json.load(f)
                        q_field = zk['q']

                    actual_c = min(c_count, num_chunks)
                    
                    import secrets
                    k1 = secrets.randbelow(q_field)
                    k2 = secrets.randbelow(q_field)
                    z = secrets.randbelow(q_field)
                    
    
                    chal_set = []
                    for i in range(actual_c):
                        chal_set.append([i, random.randint(1, q_field - 1)])
                    
                    with open("challenge.json", "w") as f:
                        json.dump({
                            "k1": k1, 
                            "k2": k2, 
                            "c": actual_c, 
                            "z": z, 
                            "challenge_set": chal_set
                        }, f)
                comm_verifier_cloud = get_file_size("challenge.json")

                with suppress_output():
                    cloud = SimpleCloudServer()
                    if os.path.exists("iot_to_cloud.enc.json"):
                        cloud.decrypt_iot_payload() 
                    cloud.load_data_from_iot()
                    cloud.receive_challenge()
                    cloud.generate_proof(stored_file=filename)
                    cloud.send_proof_to_verifier()

                comm_cloud_verifier = get_file_size("cloud_to_verifier.enc.json")
                
                bc_verify_bytes = calculate_blockchain_verify_payload(cloud)

                row = {
                    "Original Size": size,
                    "Challenge Count": actual_c,
                    "Comm: IoT->Cloud": comm_iot_cloud,
                    "Comm: IoT->Verifier": comm_iot_verifier,
                    "Comm: Verifier->Cloud": comm_verifier_cloud,
                    "Comm: Cloud->Verifier": comm_cloud_verifier,
                    "Blockchain: Store Payload": bc_store_bytes,
                    "Blockchain: Verify Payload": bc_verify_bytes,
                    "Storage: Cloud Total": storage_cloud_total,
                    "Storage Expansion Ratio": round(expansion, 2)
                }
                results.append(row)

                # Print Row
                print(f"{size:<9} | {actual_c:<7} | {comm_iot_cloud:<9} | {comm_iot_verifier:<9} | {comm_cloud_verifier:<9} | {bc_store_bytes:<9} | {bc_verify_bytes:<9} | {storage_cloud_total:<9}")

        except Exception as e:
            print(f"Error on size {size}: {e}")
        if os.path.exists(filename): os.remove(filename)

    keys = results[0].keys() if results else []
    if keys:
        with open(OUTPUT_CSV, 'w', newline='') as f:
            w = csv.DictWriter(f, keys)
            w.writeheader()
            w.writerows(results)
        print(f"\nDetailed overhead metrics saved to {OUTPUT_CSV}")

if __name__ == "__main__":
    run_overhead_analysis()