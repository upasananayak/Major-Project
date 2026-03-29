from config import HASH_ALG, PQC_SIG, PQC_KEM, AES_KEY_BYTES
import oqs
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from utils import P


def kem_keypair():
    with oqs.KeyEncapsulation(PQC_KEM) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk

def generate_sig_keypair():
    with oqs.Signature(PQC_SIG) as signer:
        pk = signer.generate_keypair()
        sk = signer.export_secret_key() 
    return pk, sk

def simple_hash(data):
    if isinstance(data, (list, tuple)):
        data = ",".join(map(str, data))
    if not isinstance(data, bytes):
        data = str(data).encode()

    if HASH_ALG.lower() in ("sha3_512", "sha3-512"):
        h = hashlib.sha3_512(data).digest()
    else:
        h = hashlib.sha512(data).digest()

    return int.from_bytes(h, "big") % P

def sign_message(sk_bytes, message: bytes):
    with oqs.Signature(PQC_SIG, secret_key=sk_bytes) as signer:
        sig = signer.sign(message)
    return sig

def encrypt_with_shared_key(shared_key: bytes, plaintext: bytes):
    assert len(shared_key) >= AES_KEY_BYTES
    key = shared_key[:AES_KEY_BYTES]
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def kem_encapsulate(server_pubkey_bytes):
    with oqs.KeyEncapsulation(PQC_KEM) as kem:
        ct, ss = kem.encap_secret(server_pubkey_bytes)
    return ct, ss  

def kem_decapsulate(server_sk_bytes, ct_bytes):
    with oqs.KeyEncapsulation(PQC_KEM, secret_key=server_sk_bytes) as kem:
        ss = kem.decap_secret(ct_bytes)
    return ss

def decrypt_with_shared_key(shared_key: bytes, ciphertext: bytes):
    key = shared_key[:AES_KEY_BYTES]
    nonce = ciphertext[:12]
    ct = ciphertext[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def verify_signature(public_key_hex: str, message_bytes: bytes, signature_hex: str) -> bool:
    sig = oqs.Signature(PQC_SIG)
    pk_bytes = bytes.fromhex(public_key_hex)
    signature_bytes = bytes.fromhex(signature_hex)
    try:
        return sig.verify(message_bytes, signature_bytes, pk_bytes)
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False