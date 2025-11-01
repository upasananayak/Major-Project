import json
import os
import secrets

from utils import pseudo_random_permutation, pseudo_random_function
from verifier import SimpleVerifier

def generate_challenge(num_chunks=None, c=5, iot_file="iot_to_verifier_dec.json"):
    
    print("Generating Challenge Parameters")

    if num_chunks is None:
        if not os.path.exists(iot_file):
            sv = SimpleVerifier()
            ok = sv.decrypt_iot_verifier_file(out_filename=iot_file)
            if not ok:
                raise RuntimeError(f"Could not obtain {iot_file} (decryption failed or files missing).")

        try:
            with open(iot_file, "r") as f:
                iot_obj = json.load(f)
            num_chunks = int(iot_obj.get("num_chunks"))
            print(f"  Read num_chunks={num_chunks} from {iot_file}")
        except Exception as e:
            raise RuntimeError(f"num_chunks not provided and could not be read from {iot_file}: {e}")
    if num_chunks <= 0:
        raise ValueError("num_chunks must be > 0")

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
    print("genchallenge ")
    
    generate_challenge(c=5)
