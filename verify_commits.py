import json, hashlib
from utils import eval_polynomial, P

def hash_commitment(poly_value, r):
    """Recompute SHA3-256 based commitment"""
    data = f"{poly_value}|{r}".encode()
    return int(hashlib.sha3_256(data).hexdigest(), 16) % P
def verify_challenged_commitments(file_a, file_b):
    """
    Robust verification for challenged commitments.

    The function accepts two JSON file paths in any order. It will try to locate:
      - polynomial_commitments and metadata.secret_psi (usually in iot_to_cloud.json)
      - challenge_set (either top-level or under challenge_metadata in the proof file)

    Typical calls that will now work:
      verify_challenged_commitments("iot_to_cloud.json", "challenge.json")
      verify_challenged_commitments("iot_to_verifier.json", "cloud_to_verifier.json")
    """

    def _load(path):
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    data_a = _load(file_a)
    data_b = _load(file_b)

    # Determine where polynomial commitments and psi live
    commits = None
    psi = None
    for candidate in (data_a, data_b):
        if candidate and 'polynomial_commitments' in candidate:
            commits = candidate['polynomial_commitments']
            psi = candidate.get('metadata', {}).get('secret_psi')
            break

    # Fallback: try to open iot_to_cloud.json if commitments weren't found
    if commits is None:
        cloud_fallback = _load('iot_to_cloud.json')
        if cloud_fallback and 'polynomial_commitments' in cloud_fallback:
            commits = cloud_fallback['polynomial_commitments']
            psi = cloud_fallback.get('metadata', {}).get('secret_psi')

    if commits is None:
        print(" Could not find 'polynomial_commitments' in provided files or iot_to_cloud.json")
        return False

    # Determine where the challenge_set lives (top-level or nested)
    challenge_obj = None
    for candidate in (data_a, data_b):
        if not candidate:
            continue
        if 'challenge_set' in candidate:
            challenge_obj = candidate
            break
        if 'challenge_metadata' in candidate and isinstance(candidate['challenge_metadata'], dict):
            if 'challenge_set' in candidate['challenge_metadata']:
                challenge_obj = candidate['challenge_metadata']
                break

    if challenge_obj is None:
        print(" No challenge_set found in provided files.")
        return False

    challenge_set = challenge_obj.get('challenge_set', [])
    if not challenge_set:
        print(" challenge_set is empty.")
        return False

    print(f"\n Verifying {len(challenge_set)} challenged polynomial commitments...\n")
    all_passed = True

    # Ensure psi is available; if missing, try to read from iot_to_cloud.json metadata
    if psi is None:
        cloud_fallback = _load('iot_to_cloud.json')
        if cloud_fallback:
            psi = cloud_fallback.get('metadata', {}).get('secret_psi')

    if psi is None:
        print(" Could not determine secret_psi (needed to recompute commitments).")
        return False

    for (chunk_id, coeff) in challenge_set:
        # defensive checks
        if chunk_id < 0 or chunk_id >= len(commits):
            print(f"  Chunk id {chunk_id} out of range (0..{len(commits)-1})")
            all_passed = False
            continue

        item = commits[chunk_id]
        coeffs = item['coeffs']
        r = item['r']
        stored_commit = item['commitment']

        # Recompute polynomial at psi
        poly_value = eval_polynomial(coeffs, psi, P)

        # Recompute commitment (must match device’s rule)
        recomputed_commit = hash_commitment(poly_value, r)

        if recomputed_commit == stored_commit:
            print(f"  Chunk {chunk_id} → Commitment verified (Coeff a_i={coeff})")
        else:
            print(f"  Chunk {chunk_id} FAILED — expected {stored_commit}, got {recomputed_commit}")
            all_passed = False

    if all_passed:
        print("\n  All challenged commitments verified successfully!")
    else:
        print("\n  Some challenged commitments failed verification.")

    return all_passed

if __name__ == "__main__":
    verify_challenged_commitments("cloud_to_verifier.json", "challenge.json")
