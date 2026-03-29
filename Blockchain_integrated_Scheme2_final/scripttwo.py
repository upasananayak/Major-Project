import subprocess
import sys
import time
import json
from collections import OrderedDict

def run_component(script, description, timings=None):
    start = time.perf_counter()
    result = subprocess.run(
        [sys.executable, script],
        capture_output=True,
        text=True
    )
    elapsed = time.perf_counter() - start
    
    if timings is not None and description == "3. CHALLENGE GENERATION":
        timings[description] = elapsed

    if result.stderr:
        print(f"STDERR from {script}:", result.stderr)

    return result.returncode == 0

def main():
    try:
        challenge_input = sys.stdin.read().strip()
        if not challenge_input:
            challenge_input = "10"
    except EOFError:
        challenge_input = "10"

    timings = OrderedDict()
    
    start = time.perf_counter()
    subprocess.run(
        [sys.executable, "generate_challenge.py"],
        input=challenge_input + "\n",
        text=True,
        capture_output=True
    )
    timings["3. CHALLENGE GENERATION"] = time.perf_counter() - start

    with open("timings_scripttwo.json", "w") as f:
        json.dump(timings, f, indent=2)

    subprocess.run([sys.executable, "cloud_server.py"], capture_output=True)
    subprocess.run([sys.executable, "verifier.py"], capture_output=True)

    print("Stage 2 Complete.")

if __name__ == "__main__":
    main()