from config import PQC_KEM, AES_KEY_BYTES
import oqs
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from utils import P
from web3 import Web3

def kem_keypair():
    with oqs.KeyEncapsulation(PQC_KEM) as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk

from eth_abi.packed import encode_packed 
def simple_hash(data, types=None, values=None):
    w3 = Web3()
    if types and values:
        processed_values = []
        for t, v in zip(types, values):
            if t == 'bytes32' and isinstance(v, str):
                processed_values.append(bytes.fromhex(v.replace('0x', '')))
            else:
                processed_values.append(v)
        
        return w3.keccak(encode_packed(types, processed_values)).hex()
    
    return w3.keccak(text=str(data)).hex()

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
