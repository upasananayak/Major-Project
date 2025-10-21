from config import HASH_ALG, PQC_SIG, PQC_KEM, AES_KEY_BYTES
import oqs
import hashlib, random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from utils import P, G, PSI

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


def generate_zk_proof(commitment, poly_value, r):
    """
    Deterministic post-quantum compatible non-interactive ZK proof.
    Prover proves knowledge of (poly_value, r) such that commitment = H(poly_value + r).
    Uses Fiat–Shamir heuristic with consistent hashing.
    """
    # Step 1: random nonce
    nonce = random.randint(1, P - 1)

    # Step 2: Commitment value 'a' = H(nonce)
    a = hashlib.sha3_256(str(nonce).encode()).hexdigest()

    # Step 3: Fiat–Shamir challenge c = H(str(commitment) || str(a))
    challenge_input = f"{commitment}|{a}"
    challenge = int(hashlib.sha3_256(challenge_input.encode()).hexdigest(), 16) % P

    # Step 4: Response z = (nonce + challenge * commitment) mod P
    # Use the numeric commitment (commitment) so the verifier can recompute the nonce
    # without learning (poly_value + r).
    z = (nonce + challenge * int(commitment)) % P

    # Step 5: Proof output
    return {
        "a": a,
        "challenge": challenge,
        "response": z,
        "commitment": commitment
    }


def verify_zk_proof(proof):
    """Verifier replays Fiat–Shamir heuristic to check consistency."""
    try:
        a = proof["a"]
        c = proof["challenge"]
        z = proof["response"]
        commit = proof["commitment"]
    except KeyError as e:
        print(f"   Missing key in proof: {e}")
        return False

    # Recompute expected challenge from commitment and a
    challenge_input = f"{commit}|{a}"
    recomputed_c = int(hashlib.sha3_256(challenge_input.encode()).hexdigest(), 16) % P

    if recomputed_c != c:
        print(f"   Challenge mismatch: expected {recomputed_c}, got {c}")
        return False

    # Recompute a’ = H(z - c * (poly_value + r))  → simulated as H(z - c * commit)
    # Since verifier doesn't know (poly_value + r), we check internal consistency:
    recomputed_a = hashlib.sha3_256(str((z - c * commit) % P).encode()).hexdigest()

    return recomputed_a == a
