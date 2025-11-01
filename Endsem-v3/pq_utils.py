from config import HASH_ALG, PQC_SIG, PQC_KEM, AES_KEY_BYTES
import oqs
import hashlib, random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from utils import P, G, PSI
from Crypto.Util import number
from Crypto.Random import random
# pq_utils.py (top)
import random as _py_random
import secrets as _secrets

def set_demo_deterministic_seed(seed_value: int = 42):
    """
    Make RNG deterministic for demo/testing:
      - seeds Python's random
      - seeds numpy (if present)
      - patches secrets.randbelow to deterministic function
      - if Crypto.Random is used, redirect its .random to Python random
    NOTE: ONLY FOR DEMO. Do NOT use in production.
    """
    # 1) seed built-in random
    _py_random.seed(seed_value)

    # 2) seed numpy if available
    try:
        import numpy as _np
        _np.random.seed(seed_value)
    except Exception:
        pass

    # 3) patch secrets.randbelow to use deterministic random.randrange
    def _deterministic_randbelow(q):
        # return value in [1, q-1], matching earlier usage
        return _py_random.randrange(1, q)
    _secrets.randbelow = _deterministic_randbelow

    # 4) try to redirect Crypto.Random.random to the python random module
    #    so code that used "from Crypto.Random import random" later sees deterministic source.
    try:
        import Crypto.Random as _crypto_rand
        # replace attribute 'random' (module) or function with wrapper:
        # If code calls _crypto_rand.random.randrange, mapping module is OK.
        _crypto_rand.random = _py_random
    except Exception:
        # Crypto not present / cannot patch; ignore
        pass

    print(f"[Demo mode] Deterministic RNG seeded with {seed_value}")

def simple_hash(data):
    """
    Use SHA3-512 (or configurable) and return an integer reduced mod P (or full hex).
    Avoid tiny 32-bit truncations.
    """
    if isinstance(data, (list, tuple)):
        data = ",".join(map(str, data))
    if not isinstance(data, bytes):
        data = str(data).encode()

    if HASH_ALG.lower() in ("sha3_512", "sha3-512"):
        h = hashlib.sha3_512(data).digest()
    else:
        h = hashlib.sha512(data).digest()

    # return hex string or integer: I prefer hex to avoid tiny integer collisions
    return int.from_bytes(h, "big") % P


def generate_sig_keypair():
    with oqs.Signature(PQC_SIG) as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key()  # bytes
    # Note: python-oqs returns keys differently; see library docs
    # Simpler approach: keep a signer instance on the device if long-lived.
    return pk, sk

def sign_message(sk_bytes, message: bytes):
    with oqs.Signature(PQC_SIG, secret_key=sk_bytes) as signer:
        sig = signer.sign(message)
    return sig

def verify_signature(public_key_hex: str, message_bytes: bytes, signature_hex: str) -> bool:
    """Verify Dilithium3 post-quantum signature"""
    sig = oqs.Signature(PQC_SIG)
    pk_bytes = bytes.fromhex(public_key_hex)
    signature_bytes = bytes.fromhex(signature_hex)
    try:
        return sig.verify(message_bytes, signature_bytes, pk_bytes)
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False
    
def kem_encapsulate(server_pubkey_bytes):
    with oqs.KeyEncapsulation(PQC_KEM) as kem:
        # If you have server public key, use kem.encapsulate(server_pubkey)
        # For local test: generate ephemeral keypair and encapsulate to own pk
        ct, ss = kem.encap_secret(server_pubkey_bytes)
    return ct, ss  # ct: bytes, ss: shared secret bytes

def kem_keypair():
    with oqs.KeyEncapsulation(PQC_KEM) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk

def kem_decapsulate(server_sk_bytes, ct_bytes):
    """Decapsulate ct -> shared secret using server secret key bytes."""
    with oqs.KeyEncapsulation(PQC_KEM, secret_key=server_sk_bytes) as kem:
        ss = kem.decap_secret(ct_bytes)
    return ss

def encrypt_with_shared_key(shared_key: bytes, plaintext: bytes):
    assert len(shared_key) >= AES_KEY_BYTES
    key = shared_key[:AES_KEY_BYTES]
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def decrypt_with_shared_key(shared_key: bytes, ciphertext: bytes):
    key = shared_key[:AES_KEY_BYTES]
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


def simple_hash_zkp(x: str) -> int:
    """Uniform SHA3-256 mod P hash."""
    return int(hashlib.sha3_256(str(x).encode()).hexdigest(), 16) % P


def generate_group_params(bits=32):
    """
    Generate safe prime p = 2q + 1, with q prime, and base g of order q.
    Returns dict: {p, q, g, h}
    WARNING: generation is expensive for large bits. Do once and persist parameters.
    """
    # getStrongPrime gives p where p-1 has large prime factor; for safer we can find q then p=2q+1
    # We'll try to find q,a prime with p=2q+1 also prime (safe prime).
    while True:
        print("Generating safe prime...")
        q = number.getPrime(bits - 1)  # q roughly bits-1
        p = 2 * q + 1
        if number.isPrime(p):
            break
    # find a generator g of the order-q subgroup
    # pick random a in [2, p-2], set g = a^2 mod p to ensure it lies in subgroup? Safer to test.
    while True:
        print("Finding generator g...")
        a = random.randrange(2, p - 1)
        g = pow(a, 2, p)  # squaring eliminates sign and often gives element of order q
        if g != 1:
            # ensure g^q mod p == 1
            if pow(g, q, p) == 1:
                break
    # pick h as another independent generator: h = g^alpha with alpha random
    alpha = random.randrange(2, q - 1)
    h = pow(g, alpha, p)
    print(f"Generated params: p ({bits} bits), q ({bits-1} bits), g, h.")
    return {"p": p, "q": q, "g": g, "h": h}

# You should generate params once, persist them, and reuse. Example:
# PARAMS = generate_group_params(2048)
# For convenience, we provide a small test-params generator for demo (NOT for production)
def demo_group_params():
    #  insecure, for demo only
    p = 2147483647               # 2^31 - 1
    q = (p - 1) // 2             # 1073741823
    g = 5                        # generator of subgroup (works mod this p)
    h = pow(g, 2, p)             # secondary generator
    return {"p": p, "q": q, "g": g, "h": h}


# ------------ Pedersen commitment ------------
def pedersen_commit(m, r, params):
    """
    Compute commitment C = g^m * h^r mod p.
    m, r are integers (plaintexts), params is dict from generate_group_params().
    """
    p = params["p"]
    g = params["g"]
    h = params["h"]
    gm = pow(g, m % params["q"], p)
    hr = pow(h, r % params["q"], p)
    C = (gm * hr) % p
    return C

# ------------ Schnorr-style non-interactive proof ------------
def hash_to_int(*args, q=None):
    """
    Hash arbitrary args (numbers/bytes/strings) to integer modulo q (if q provided)
    """
    m = b"|".join(
        a if isinstance(a, (bytes, bytearray)) else str(a).encode()
        for a in args
    )
    digest = hashlib.sha256(m).digest()
    val = int.from_bytes(digest, "big")
    if q:
        return val % q
    return val


def generate_zk_proof(commitment, poly_value, r, params):
    p = params["p"]
    q = params["q"]
    g = params["g"]
    h = params["h"]

    # Use secrets.randbelow (will be deterministic in demo mode after set_demo_deterministic_seed)
    t = _secrets.randbelow(q)
    s = _secrets.randbelow(q)

    A = (pow(g, t, p) * pow(h, s, p)) % p

    # Fiat-Shamir
    c = hash_to_int(commitment, A, q=q)

    u = (t + (c * (poly_value % q))) % q
    v = (s + (c * (r % q))) % q

    return {
        "A": int(A),
        "c": int(c),
        "u": int(u),
        "v": int(v),
        "commitment": int(commitment)
    }


def verify_zk_proof(proof, params):
    try:
        A = int(proof["A"])
        c = int(proof["c"])
        u = int(proof["u"])
        v = int(proof["v"])
        commitment = int(proof["commitment"])
    except KeyError as e:
        print(f"Missing key in proof: {e}")
        return False

    p = params["p"]
    q = params["q"]
    g = params["g"]
    h = params["h"]

    lhs = (pow(g, u, p) * pow(h, v, p)) % p
    rhs = (A * pow(commitment, c % q, p)) % p

    if lhs != rhs:
        print("Invalid proof: group equation does not hold.")
        # helpful debug values
        print(f"lhs = g^u * h^v mod p = {lhs}")
        print(f"rhs = A * commitment^c mod p = {rhs}")
        return False

    # recompute challenge to ensure Fiat-Shamir consistency
    recomputed_c = hash_to_int(commitment, A, q=q)
    if recomputed_c != c % q:
        print(f"Challenge mismatch: expected {recomputed_c}, got {c}")
        return False

    return True

# ------------ Utilities to integrate with your code ------------
# Example wrapper: Prover side
def prove_chunk(commit_data, psi, params):
    """
    commit_data: dict with keys 'coeffs', 'r', 'commitment'
    psi: secret_psi used to evaluate polynomial (kept secret)
    params: group params
    Returns proof dict (no psi, no r, no poly_value)
    """

    coeffs = commit_data["coeffs"]
    r = int(commit_data["r"])
    commitment = int(commit_data["commitment"])

    # evaluate polynomial modulo q (exactly how commitment was created)
    from utils import eval_polynomial
    # IMPORTANT: reduce modulo params['q'] so exponentiation matches pedersen_commit
    poly_value = int(eval_polynomial(coeffs, psi, params["q"])) % params["q"]

    # Debug check: recompute commitment and ensure it equals stored commitment
    recomputed = pedersen_commit(poly_value, r, params)
    if recomputed != commitment:
        # Very important diagnostic output to pin down mismatch
        print("=== Commitment mismatch BEFORE creating ZK proof ===")
        print(f"Stored commitment:  {commitment}")
        print(f"Recomputed commit:  {recomputed}")
        print("Possible causes: different params (p,q,g,h), different reduction (P vs q), or r mismatch.")
        raise ValueError("Commitment mismatch: cannot create valid ZK proof for inconsistent data.")

    # generate actual ZK proof (non-interactive Schnorr/Pedersen style)
    proof = generate_zk_proof(commitment, poly_value, r, params)
    return proof

# Example wrapper: Verifier side
def verify_chunk_proof(proof, params):
    """
    proof: proof dict from prove_chunk
    params: same group params
    Returns True/False
    """
    return verify_zk_proof(proof, params)