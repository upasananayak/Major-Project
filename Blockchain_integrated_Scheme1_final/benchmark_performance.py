#!/usr/bin/env python3
import os
import sys
import time
import json
import csv
import argparse
import subprocess
from pathlib import Path
import uuid

# Paths
ROOT_DIR = Path(__file__).resolve().parent
IOT_TIMINGS_FN = "timings_scriptone.json"
VERIFIER_TIMINGS_FN = "timings_scripttwo.json"
OUT_CSV = ROOT_DIR / "benchmarks" / "benchmark_results_50.csv"
BLOCKCHAIN_METRICS_FN = "blockchain_tx_metrics.json"

# The scripts to run
SCRIPT_ONE = "scriptone.py" 
SCRIPT_TWO = "scripttwo.py" 

def get_time_from_json(json_path, key):
    try:
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
                return float(data.get(key, 0.0))
    except Exception as e:
        print(f"Error reading {key} from {json_path}: {e}")
    return 0.0

def get_gas_from_json(json_path, tx_name):
    """Helper to extract gasUsed for a specific transaction."""
    try:
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
                return data.get(tx_name, {}).get("gasUsed", 0)
    except Exception as e:
        print(f"Error reading gas for {tx_name} from {json_path}: {e}")
    return 0

def run_experiment(file_size, challenge_c):
    # 1. Create a temporary dummy file
    for temp_file in ["iot_to_cloud.enc.json", "iot_to_verifier.enc.json", 
                     "iot_to_cloud_dec.json", "iot_to_verifier_dec.json", "challenge.json",BLOCKCHAIN_METRICS_FN]:
        if os.path.exists(temp_file):
            os.remove(temp_file)
            
    # test_filename = f"test_{file_size}.bin"
    # test_file_path = ROOT_DIR / test_filename
    unique_suffix = uuid.uuid4().hex[:6]
    test_filename = f"test_{file_size}_{challenge_c}_{unique_suffix}.bin"
    test_file_path = ROOT_DIR / test_filename
    with open(test_file_path, "wb") as f:
        f.write(os.urandom(file_size))

    # 2. RUN STAGE 1 (Setup & Store)
    print(f"--- Running {SCRIPT_ONE} | Size: {file_size} bytes ---")
    subprocess.run(
        [sys.executable, SCRIPT_ONE],
        input=f"{test_filename}\n",
        text=True,
        capture_output=False
    )
    
    setup_t = get_time_from_json(IOT_TIMINGS_FN, "1. SETUP  TIME")
    store_t = get_time_from_json(IOT_TIMINGS_FN, "2. STORE TIME")
    reg_gas = get_gas_from_json(BLOCKCHAIN_METRICS_FN, "registerFile")
    upd_gas = get_gas_from_json(BLOCKCHAIN_METRICS_FN, "updateFile")

    # 3. RUN STAGE 2 (Challenge, Proof Gen, Verification)
    print(f"--- Running {SCRIPT_TWO} | C={challenge_c} ---")
    subprocess.run(
        [sys.executable, SCRIPT_TWO],
        input=f"{challenge_c}\n", 
        text=True,
        capture_output=False
    )

    chal_t = get_time_from_json(VERIFIER_TIMINGS_FN, "3. CHALLENGE GENERATION")
    p_gen_t = get_time_from_json(VERIFIER_TIMINGS_FN, "4. PROOF GENERATION (Cloud)")
    p_ver_t = get_time_from_json(VERIFIER_TIMINGS_FN, "5. PROOF VERIFICATION")

    veri_gas = get_gas_from_json(BLOCKCHAIN_METRICS_FN, "submitVerification")
    # Cleanup
    if os.path.exists(test_file_path):
        os.remove(test_file_path)

    return {
        "file_size": file_size,
        "challenge_c": challenge_c,
        "setup_time": f"{setup_t:.10f}", 
        "store_time": f"{store_t:.10f}",
        "chalgen_time": f"{chal_t:.10f}",
        "proofgen_time": f"{p_gen_t:.10f}",
        "proofveri_time": f"{p_ver_t:.10f}",
        "total": f"{(setup_t + store_t + chal_t + p_gen_t + p_ver_t):.10f}",
        "register_gas": reg_gas,
        "update_gas": upd_gas,
        "verify_gas": veri_gas
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file-sizes", nargs="+", type=int, default=[16384, 32768, 65536, 131072, 262144, 524288]) # 512B to 1MB
    parser.add_argument("--challenges", nargs="+", type=int, default=[1,5,10,20,50,100,200,300,600])
    args = parser.parse_args()

    results = []
    for fs in args.file_sizes:
        for c in args.challenges:
            data = run_experiment(fs, c)
            results.append(data)

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\nBenchmark Complete. Data saved to {OUT_CSV}")

if __name__ == "__main__":
    main()
