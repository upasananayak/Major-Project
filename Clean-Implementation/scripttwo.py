"""
scripttwo.py
============
Stage 2: Cloud + Verifier Verification

This script runs the second half of the workflow:
1. Decrypts the IoT and cloud payloads.
2. Cloud generates proof.
3. Verifier checks integrity and ZK proofs.
If you modified the original file after Stage 1, verification will FAIL.
"""

import subprocess
import sys

def run_component(script, description):
    print("="*60)
    print(f" {description} ")
    print("="*60)

    result = subprocess.run([sys.executable, script], capture_output=True, text=True)

    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    print(f"\n=== {description} Completed ===")
    
    return result.returncode == 0

def main():
    challenge_ok = run_component("generate_challenge.py", "3. CHAL")
    if not challenge_ok:
        print("Challenge Generation failed. Aborting verification.")
        return
    
    cloud_ok = run_component("cloud_server.py", "4. PROOF GEN")
    if not cloud_ok:
        print(" Cloud server failed. Aborting verification.")
        return

    # Verifier checks integrity + ZK proof
    verifier_ok = run_component("verifier.py", "5. PROOF VERI")
    if verifier_ok:
        print("\n Verification PASSED — Data integrity confirmed.")
    else:
        print("\n Verification FAILED — Data modified or tampered.")

    print("Stage 2 complete.")

if __name__ == "__main__":
    main()
