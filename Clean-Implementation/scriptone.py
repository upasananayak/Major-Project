import os
import subprocess
import sys

def ensure_keys_and_params():
    if not (os.path.exists("server_kem_pub.b64") and os.path.exists("server_kem_sk.b64")):
        print("Generating server KEM keypair")
        subprocess.run([sys.executable, "config.py"])

    print("\n")

    if not os.path.exists("zk_params.json"):
        print("Generating ZK parameters")
        subprocess.run([sys.executable, "generate_params.py"])

def main():
    print("="*60)
    print(" 1. SETUP")
    print("="*60)

    ensure_keys_and_params()

    print("\n=== Setup Completed ===")

    print("="*60)
    print(" 2. STORE")
    print("="*60)

    result = subprocess.run([sys.executable, "iot_simulation.py"], text=True)
    print("\n=== Store Completed ===")

    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)

    print("="*60)
    print("Data encrypted and uploaded to:")
    print("   • iot_to_cloud.enc.json")
    print("   • iot_to_verifier.enc.json")
    print("="*60)

if __name__ == "__main__":
    main()
