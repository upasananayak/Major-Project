import os
import subprocess
import sys
import time
import json
from collections import OrderedDict

def ensure_keys_and_params():
    if not (os.path.exists("server_kem_pub.b64") and os.path.exists("server_kem_sk.b64")):
        # print("Generating server KEM keypair")
        subprocess.run([sys.executable, "config.py"], check=True)

    if not os.path.exists("zk_params.json"):
        # print("Generating ZK parameters")
        subprocess.run([sys.executable, "generate_params.py"], check=True)

def main():
    timings = OrderedDict()

    # print("="*70)
    # print(" STAGE 1: SETUP")
    # print("="*70)

    start = time.perf_counter()
    ensure_keys_and_params()
    timings["1. SETUP  TIME"] = time.perf_counter() - start

    # print("\n=== Setup Completed ===\n")

    # print("="*70)
    # print(" STAGE 2: STORE (IoT → Cloud → Blockchain)")
    # print("="*70)

    try:
        input_filename = sys.stdin.read().strip()
    except EOFError:
        input_filename = ""

    start = time.perf_counter()

    # print("Input received by IOT:" ,input_filename)
    result = subprocess.run(
        [sys.executable, "iot_simulation.py"],
        input=input_filename + "\n", # Pass the filename down the chain
        text=True,
        capture_output=True
    )
    timings["2. STORE TIME"] = time.perf_counter() - start

    # print("\n=== Store Completed ===\n")

    # print(result.stdout)
    if result.stderr:
             print("STDERR:", result.stderr)

    # print("="*60)
    # print("Data encrypted and uploaded to:")
    # print("   • iot_to_cloud.enc.json")
    # print("   • iot_to_verifier.enc.json")
    # print("="*60)

    # print("\n" + "="*70)
    # print(" FINAL TIMING REPORT")
    # print("="*70)

    total = 0
    for stage, t in timings.items():
        #print(f" {stage:<45} : {t*1000:.2f} ms")
        total += t

    # print("-"*70)
    # print(f" TOTAL EXECUTION TIME{'':<28} : {total*1000:.2f} ms")
    # print("="*70)

    timings["Total setup+store time"] = sum(timings.values())

    with open("timings_scriptone.json", "w") as f:
     json.dump(timings, f, indent=2)

if __name__ == "__main__":
    main()

