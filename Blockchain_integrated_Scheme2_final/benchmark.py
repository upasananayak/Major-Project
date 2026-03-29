import os
import sys
import time
import json
import csv
import argparse
import subprocess
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
IOT_TIMINGS_FN ="timings_scriptone.json"
VERIFIER_TIMINGS_FN ="timings_scripttwo.json"
OUT_CSV = ROOT_DIR / "benchmarks" / "benchmark_results_50.csv"


SCRIPT_ONE = "scriptone.py" # Setup & Store
SCRIPT_TWO = "scripttwo.py" # Chalgen, ProofGen, ProofVeri

GAS_TIMINGS_FN = "gas_timings.json"

def get_time_from_json(json_path, key):
    try:
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
                return float(data.get(key, 0.0))
    except Exception as e:
        print(f"Error reading {key} from {json_path}: {e}")
    return 0.0

def run_experiment(file_size, challenge_c, chalgen_approach="json"):
    test_filename = f"test_{file_size}.bin"
    test_file_path = ROOT_DIR / test_filename
    with open(test_file_path, "wb") as f:
        f.write(os.urandom(file_size))

    # 2. RUN SCRIPT ONE (IoT: Setup, Store)
    print(f"--- Running {SCRIPT_ONE} for size {file_size} ---")
    subprocess.run(
        [sys.executable, SCRIPT_ONE],
        input=f"{test_filename}\n",
        text=True,
        capture_output=False
    )
  
    
    setup_t = get_time_from_json(IOT_TIMINGS_FN, "1. SETUP  TIME")
    store_t = get_time_from_json(IOT_TIMINGS_FN, "2. STORE TIME")
    reg_gas = get_time_from_json(GAS_TIMINGS_FN, "REGISTER_GAS")


    # 3. RUN SCRIPT TWO (Cloud/Verifier: ChalGen, ProofGen, ProofVeri)
    print(f"--- Running {SCRIPT_TWO} with C={challenge_c} ---")
    
    start_manual = time.time()
    sub_res = subprocess.run(
        [sys.executable, SCRIPT_TWO],
        input=f"{challenge_c}\n", 
        text=True,
        capture_output=True
    )
    end_manual = time.time()


    chal_t = get_time_from_json(VERIFIER_TIMINGS_FN, "3. CHALLENGE GENERATION")

    p_gen_t = get_time_from_json(VERIFIER_TIMINGS_FN, "4. PROOF GENERATION (Cloud)")
    p_ver_t = get_time_from_json(VERIFIER_TIMINGS_FN, "5. PROOF VERIFICATION")
    ver_gas = get_time_from_json(GAS_TIMINGS_FN, "VERIFY_GAS")

    print(setup_t)
    print(store_t)


    if os.path.exists(test_file_path):
        os.remove(test_file_path)

   
    return {
        "file_size": file_size,
        "challenge_c": challenge_c,
        "setup_time": f"{setup_t:.10f}", 
        "store_time": f"{store_t:.10f}",
        "reg_gas": int(reg_gas),       
        "ver_gas": int(ver_gas),
        "chalgen_time": f"{chal_t:.10f}",
        "proofgen_time": f"{p_gen_t:.10f}",
        "proofveri_time": f"{p_ver_t:.10f}",
        "total": f"{(setup_t + store_t + chal_t + p_gen_t + p_ver_t):.10f}"
    }

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--file-sizes", nargs="+", type=int,
                         default=[1024],
                        help="File sizes in bytes.")
    parser.add_argument("--challenges", nargs="+", type=int,
                        default=[20],
                        help="Challenge sizes to test.")
    parser.add_argument("--runs", type=int, default=1,
                        help="Repeat each experiment N times and average.")
    parser.add_argument("--out", default=str(OUT_CSV))
    args = parser.parse_args()

    results= []
    for fs in args.file_sizes:
        for c in args.challenges:
            data = run_experiment(fs, c, chalgen_approach="json")
            print(data)
            results.append(data)

    os.makedirs(os.path.dirname(OUT_CSV), exist_ok=True)
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    
    print(f"\nBenchmark Complete. Data saved to {OUT_CSV}")

if __name__ == "__main__":
    main()
