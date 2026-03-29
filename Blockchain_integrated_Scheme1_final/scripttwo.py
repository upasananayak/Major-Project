# """
# scripttwo.py
# ============
# Stage 2: Cloud + Verifier Verification

# This script runs the second half of the workflow:
# 1. Decrypts the IoT and cloud payloads.
# 2. Cloud generates proof.
# 3. Verifier checks integrity and ZK proofs.
# If you modified the original file after Stage 1, verification will FAIL.
# """

# import subprocess
# import sys

# def run_component(script, description):
#     print("="*60)
#     print(f" {description} ")
#     print("="*60)

#     result = subprocess.run([sys.executable, script], capture_output=True, text=True)

#     print(result.stdout)
#     if result.stderr:
#         print("STDERR:", result.stderr)
#     print(f"\n=== {description} Completed ===")
    
#     return result.returncode == 0

# def main():
#     challenge_ok = run_component("generate_challenge.py", "3. CHAL")
#     if not challenge_ok:
#         print("Challenge Generation failed. Aborting verification.")
#         return
    
#     cloud_ok = run_component("cloud_server.py", "4. PROOF GEN")
#     if not cloud_ok:
#         print(" Cloud server failed. Aborting verification.")
#         return

#     # Verifier checks integrity + ZK proof
#     verifier_ok = run_component("verifier.py", "5. PROOF VERI")
#     if verifier_ok:
#         print("\n Verification PASSED — Data integrity confirmed.")
#     else:
#         print("\n Verification FAILED — Data modified or tampered.")

#     print("Stage 2 complete.")

# if __name__ == "__main__":
#     main()
"""
scripttwo.py
============
Stage 2: Cloud + Verifier Verification (Timed)

1. Challenge generation
2. Cloud proof generation
3. Proof verification
"""

import subprocess
import sys
import time
import json
from collections import OrderedDict


def run_component(script, description, timings, arg=None):
    # print("=" * 60)
    # print(f" {description} ")
    # print("=" * 60)

    start = time.perf_counter()
    cmd = [sys.executable, script]
    if arg:
        cmd.append(arg)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )
    elapsed = time.perf_counter() - start
    timings[description] = elapsed

    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    # print(f"\n=== {description} Completed in {elapsed*1000:.2f} ms ===")
    return result.returncode == 0


def main():
    timings = OrderedDict()
    stage2_start = time.perf_counter()

    import sys
    try:
        # Read the 'c' value sent by the benchmark script
        input_data = sys.stdin.readline().strip()
        challenge_c = input_data if input_data else "5" # Default to 5 if empty
    except EOFError:
        challenge_c = "5"
    # ---------------- CHALLENGE ----------------
    challenge_ok = run_component(
        "generate_challenge.py",
        "3. CHALLENGE GENERATION",
        timings,
        challenge_c
    )
    if not challenge_ok:
        print(" Challenge Generation failed. Aborting verification.")
        return

    # ---------------- PROOF GENERATION ----------------
    cloud_ok = run_component(
        "cloud_server.py",
        "4. PROOF GENERATION (Cloud)",
        timings
    )
    if not cloud_ok:
        print(" Cloud server failed. Aborting verification.")
        return

    # ---------------- PROOF VERIFICATION ----------------
    verifier_ok = run_component(
        "verifier.py",
        "5. PROOF VERIFICATION",
        timings
    )

    if verifier_ok:
        print("\n Verification PASSED — Data integrity confirmed.")
    else:
        print("\n Verification FAILED — Data modified or tampered.")

    timings["Total Stage-2 Time"] = time.perf_counter() - stage2_start

 

    with open("timings_scripttwo.json", "w") as f:
     json.dump(timings, f, indent=2)

    # ---------------- FINAL REPORT ----------------
    # print("\n" + "=" * 60)
    # print(" STAGE-2 TIMING REPORT")
    # print("=" * 60)

    # for stage, t in timings.items():
    #     # print(f" {stage:<35} : {t*1000:.2f} ms")

    # print("=" * 60)
    # print("Stage 2 complete.")

if __name__ == "__main__":
    main()

