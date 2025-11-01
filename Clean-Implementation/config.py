PQC_KEM = "Kyber512"
PQC_SIG = "Dilithium2"
HASH_ALG = "sha3_512"
AES_KEY_BYTES = 32  

SERVER_KEM_PUB = "server_kem_pub.b64"
SERVER_KEM_SK = "server_kem_sk.b64"

import os, base64

if __name__ == "__main__":   
    if os.path.exists(SERVER_KEM_PUB) and os.path.exists(SERVER_KEM_SK):
        print("Server KEM files already exist.")
    else:
        from pq_utils import kem_keypair
        pk, sk = kem_keypair()
        with open(SERVER_KEM_PUB, "w") as f:
            f.write(base64.b64encode(pk).decode())
        with open(SERVER_KEM_SK, "w") as f:
            f.write(base64.b64encode(sk).decode())
        print(f"Generated KEM keypair : {SERVER_KEM_PUB}, {SERVER_KEM_SK}")