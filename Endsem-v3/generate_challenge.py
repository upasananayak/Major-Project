"""
generate_challenge.py
Generates post-quantum safe challenge parameters for IIoT cloud verification.
"""

import json
import secrets
import hashlib

from utils import pseudo_random_permutation, pseudo_random_function
# def pseudo_random_function(k, x):
#     """Pseudo-random function (simple hash-based demo)."""
#     data = f"{k}|{x}".encode()
#     return int(hashlib.sha3_256(data).hexdigest(), 16)

# def pseudo_random_permutation(k, x):
#     """Simple pseudo-random permutation (for chunk indices)."""
#     return pseudo_random_function(k, x) ^ x

# ...existing code...
def generate_challenge(num_chunks=None, c=5, iot_file="iot_to_verifier_dec.json"):
    """
    Generate challenge JSON file to send to the cloud.
    If num_chunks is None, attempt to read it from iot_to_verifier_dec.json.
    """
    print("=== Generating Challenge Parameters ===")

    # try to read num_chunks from IoT -> Verifier JSON if not supplied
    if num_chunks is None:
        try:
            with open(iot_file, "r") as f:
                iot_obj = json.load(f)
            num_chunks = int(iot_obj.get("num_chunks"))
            print(f"  Read num_chunks={num_chunks} from {iot_file}")
        except Exception as e:
            raise RuntimeError(f"num_chunks not provided and could not be read from {iot_file}: {e}")

    # defensive check
    if num_chunks <= 0:
        raise ValueError("num_chunks must be > 0")

    # ensure c (number of challenged chunks) is not larger than num_chunks
    if c > num_chunks:
        print(f"  Warning: requested c={c} > num_chunks={num_chunks}; c will be reduced to {num_chunks}")
        c = num_chunks

    k1 = secrets.randbits(64)
    k2 = secrets.randbits(64)
    z = secrets.randbits(128)

    challenge_set = []
    seen = set()
    l = 1
    while len(challenge_set) < c:
        chunk_id = pseudo_random_permutation(k1, l, num_chunks)
        # avoid duplicates
        if chunk_id in seen:
            l += 1
            continue
        seen.add(chunk_id)
        coefficient = pseudo_random_function(k2, l, num_chunks)
        challenge_set.append((chunk_id, coefficient))
        l += 1

    challenge_data = {
        "k1": k1,
        "k2": k2,
        "c": c,
        "z": z,
        "challenge_set": challenge_set
    }

    with open("challenge.json", "w") as f:
        json.dump(challenge_data, f, indent=2)

    print(" challenge.json created successfully!")
    print(f"  k1={k1}, k2={k2}, c={c}, z={z}")
    print(f"  Challenge Set: {challenge_set}")

if __name__ == "__main__":
    # Example usage: assuming 50 file chunks exist
    generate_challenge(c=7)
