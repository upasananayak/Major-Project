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

    print("Stage 2 complete.")

if __name__ == "__main__":
    main()
