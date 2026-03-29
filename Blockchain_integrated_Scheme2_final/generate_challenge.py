import base64
import json
import os
import secrets

from config import SERVER_KEM_SK
from pq_utils import decrypt_with_shared_key, kem_decapsulate
from utils import pseudo_random_permutation, pseudo_random_function

def decrypt_iot_verifier_file(enc_filename="iot_to_verifier.enc.json", out_filename="iot_to_verifier_dec.json"):
    
        # print("\n Decrypting IoT to Verifier encrypted payload (if present)")
        if not os.path.exists(enc_filename):
            print(f"   Encrypted verifier file not found: {enc_filename} (skipping decryption)")
            return False

        if not os.path.exists(SERVER_KEM_SK):
            print(f"   Server KEM secret not found: {SERVER_KEM_SK}. Run `python3 config.py` to generate keys.")
            return False

        try:
            with open(enc_filename, "r") as f:
                obj = json.load(f)

            ct = base64.b64decode(obj["ct"])
            enc_payload = base64.b64decode(obj["enc_payload"])

            with open(SERVER_KEM_SK, "r") as f:
                server_sk = base64.b64decode(f.read().strip())

            shared = kem_decapsulate(server_sk, ct)
            plaintext = decrypt_with_shared_key(shared, enc_payload)
            payload_json = json.loads(plaintext.decode())


            with open(out_filename, "w") as out_f:
                json.dump(payload_json, out_f, indent=2)

            # print(f"   Decrypted verifier payload written to: {out_filename}")
            return True
        except Exception as e:
            print(f"   Decryption failed: {e}")
            return False
        
def generate_challenge(num_chunks=None, c=5, iot_file="iot_to_verifier_dec.json"):
    
    # print("Generating Challenge Parameters")

    ok = decrypt_iot_verifier_file(out_filename=iot_file)
    if not ok:
        raise RuntimeError(f"Could not decrypt latest IoT payload to {iot_file}")

    try:
        with open(iot_file, "r") as f:
            iot_obj = json.load(f)
        num_chunks = int(iot_obj.get("num_chunks"))
        # print(f"  Read updated num_chunks={num_chunks} from {iot_file}")
    except Exception as e:
        raise RuntimeError(f"Could not read updated num_chunks from {iot_file}: {e}")
    
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

    # print(" challenge.json created successfully!")
    # print(f"  k1={k1}, k2={k2}, c={c}, z={z}")
    # print(f"  Challenge Set: {challenge_set}")

if __name__ == "__main__":
    # print("genchallenge ")
    
    c_input = int(input("Enter challenge size c: "))
    generate_challenge(c=c_input)
    
    