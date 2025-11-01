#!/usr/bin/env python3
"""
Simple Cloud Server - IIoT Storage Verification System
Based on the IEEE paper's ProofGen algorithm
"""
# from pq_utils import set_demo_deterministic_seed
# set_demo_deterministic_seed()

import base64
import hashlib
import json
import os
import random
from config import SERVER_KEM_PUB, SERVER_KEM_SK
from utils import HHF, eval_polynomial, P, PSI, pseudo_random_permutation, pseudo_random_function
from pq_utils import decrypt_with_shared_key, encrypt_with_shared_key, generate_zk_proof, kem_decapsulate, kem_encapsulate, simple_hash, prove_chunk
import numpy.polynomial.polynomial as PolyDiv
import numpy as np


class SimpleCloudServer:
    def __init__(self):
        """Initialize cloud server"""
        print(" Initializing Simple Cloud Server")
        self.stored_data = None
        self.received_data = False
        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)
        print("ZK PARAMS fingerprint:", (self.ZK_PARAMS["p"] % 2**32, self.ZK_PARAMS["q"] % 2**32))
        # ADD THIS BLOCK (paste into IoT, Cloud, and Verifier startup)
        with open("zk_params.json", "r") as _f:
            zk = json.load(_f)
        print("ZK PARAMS check: p,q (truncated):", zk["p"] % 2**64, zk["q"] % 2**64)
        print("ZK PARAMS check: g,h (truncated):", int(zk["g"]) % 2**64, int(zk["h"]) % 2**64)
        # optional assert to fail fast if mismatch:
        assert hasattr(self, "ZK_PARAMS") and self.ZK_PARAMS["p"] == zk["p"] and self.ZK_PARAMS["g"] == zk["g"] and self.ZK_PARAMS["h"] == zk["h"], "ZK_PARAMS mismatch! Make sure zk_params.json is the same for Cloud"



    def load_data_from_iot(self, filename="iot_to_cloud_dec.json"):
        """Step 1: Load data uploaded by IoT device"""
        print(f"\n STEP 1: Loading Data from IoT Device")
        
        try:
            with open(filename, 'r') as f:
                self.stored_data = json.load(f)

            # self.file_chunks = self.stored_data["file_chunks"]
            self.homomorphic_tags = self.stored_data["homomorphic_tags"]
            # self.polynomial_commitments = self.stored_data["polynomial_commitments"]
            self.metadata = self.stored_data["metadata"]
            self.random_values = self.stored_data["random_values"]
            self.blocks_per_chunk = int(self.metadata.get("blocks_per_chunk", 4))

            # print(f"   Loaded {len(self.file_chunks)} file chunks")
            print(f"   Loaded {len(self.homomorphic_tags)} homomorphic tags")
            print(f"   Metadata: {self.metadata}")
            print(f"   Loaded {len(self.random_values)} random values for chunks")
            print(f"   Blocks per chunk: {self.blocks_per_chunk}")
            self.received_data = True
            return True
            
        except FileNotFoundError:
            print(f"   Error: {filename} not found. Run IoT simulation first!")
            return False
        

    def decrypt_iot_payload(self, enc_filename="iot_to_cloud.enc.json", out_filename="iot_to_cloud_dec.json"):
        """Read encrypted file from IoT, decapsulate with server SK, decrypt and write JSON."""
        print("\n PRESTEP: Decrypting IoT -> Cloud encrypted payload (if present)")
        if not os.path.exists(enc_filename):
            print(f"   Encrypted file not found: {enc_filename} (skipping decryption)")
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

            # decapsulate and decrypt
            shared = kem_decapsulate(server_sk, ct)
            plaintext = decrypt_with_shared_key(shared, enc_payload)
            payload_json = json.loads(plaintext.decode())

            # write decrypted JSON for later steps
            with open(out_filename, "w") as out_f:
                json.dump(payload_json, out_f, indent=2)

            print(f"   Decrypted payload written to: {out_filename}")
            # update internal state so subsequent load_data_from_iot can proceed
            self.stored_data = payload_json
            self.received_data = True
            return True
        except Exception as e:
            print(f"   Decryption failed: {e}")
            return False

    def receive_challenge(self, filename="challenge.json"):
        """Step 2: Receive challenge from Verifier (post-quantum ZK version)"""
        print(f"\n STEP 2: Receiving Challenge from Verifier")

        if not self.received_data:
            print("   Error: No IoT data loaded yet!")
            return None

        with open(filename, "r") as f:
            chal = json.load(f)

        self.k1 = chal["k1"]
        self.k2 = chal["k2"]
        self.c = chal["c"]
        self.z = chal["z"]
        self.challenge_set = chal["challenge_set"]

        print(f"   Loaded challenge: k1={self.k1}, k2={self.k2}, c={self.c}, z={self.z}")
        print(f"   Challenge set: {self.challenge_set}")

        return self.challenge_set

    def read_file_chunks(self, filename="iot_data_file.txt"):
        """Read the stored file and split into chunks like IoT."""
        with open(filename, "rb") as f:
            data = f.read()

        chunks = []
        for i in range(0, len(data), self.blocks_per_chunk):
            chunk_bytes = data[i:i+self.blocks_per_chunk]
            # Convert each byte to same 0–20 range as IoT
            chunk_blocks = [(b % 21) for b in chunk_bytes]
            while len(chunk_blocks) < self.blocks_per_chunk:
                chunk_blocks.append(0)
            chunks.append(chunk_blocks)
        return chunks

    # def generate_zk_hash_proof(self, chunk_bytes, r, commitment, z, a_i):
    #     """Generate post-quantum hash-based zero-knowledge proof."""
    #     # Fiat–Shamir challenge (depends on verifier challenge z)
    #     c_i = hashlib.sha3_256(
    #         str(commitment).encode() + str(z).encode() + str(a_i).encode()
    #     ).digest()

    #     # The ZK “response” R links c_i and the commitment through a binding hash
    #     R = hashlib.sha3_256(c_i + str(commitment).encode()).hexdigest()

    #     return {
    #         "R": R,
    #         "commitment": commitment,
    #         "c_i": c_i.hex(),
    #         "a_i": a_i
    #     }

    # def generate_zk_hash_proof(self, z, challenge_set):
    #     """
    #     Generate a challenge-dependent ZK proof using linear combination of chunks.
    #     Cloud cannot precompute this in advance since z and a_i are unknown.
    #     """
    #     P = self.ZK_PARAMS["p"] % 2**32 # or whatever modulus you’re using
    #     m_sum = 0
    #     r_sum = 0

    #     for (chunk_id, a_i) in challenge_set:
    #         m_i = int.from_bytes(bytes(self.file_chunks[chunk_id]), 'big') % P
    #         r_i = self.random_values[chunk_id] % P
    #         m_sum = (m_sum + a_i * m_i) % P
    #         r_sum = (r_sum + a_i * r_i) % P

    #     # Compute challenge-dependent binding
    #     combined_hash_input = (
    #         str(m_sum).encode() + str(r_sum).encode() + str(z).encode()
    #     )
    #     proof_value = hashlib.sha3_256(combined_hash_input).hexdigest()

    #     return {
    #         "proof_value": proof_value,
    #         "m_sum": m_sum,
    #         "r_sum": r_sum,
    #     }
    # def generate_zk_hash_proof(self, z, challenge_set):
    #     P = self.ZK_PARAMS["p"]
    #     m_sum = 0
    #     r_sum = 0
    #     C_agg = 1

    #     for (chunk_id, a_i) in challenge_set:
    #         print("a_i:", a_i)
    #         m_i = int.from_bytes(bytes(self.file_chunks[chunk_id]), 'big') % P
    #         r_i = self.random_values[chunk_id] % P
    #         C_i = int(hashlib.sha3_256(bytes(self.file_chunks[chunk_id]) + r_i.to_bytes(8, "big")).hexdigest(), 16) % P

    #         m_sum = (m_sum + a_i * m_i) % P
    #         r_sum = (r_sum + a_i * r_i) % P
    #         C_agg = (C_agg * pow(C_i, a_i, P)) % P  # ← aggregate commitment
    #         print("m_i,",m_i, "r_i:",r_i, "C_i:",C_i, "m_sum", m_sum, "r_sum", r_sum, "C_agg", C_agg)

    #     proof_value = hashlib.sha3_256(str(m_sum).encode() + str(r_sum).encode() + str(z).encode()).hexdigest()
    #     print("proof_value:", proof_value)
    #     return {
    #         "proof_value": proof_value,
    #         "m_sum": m_sum,
    #         "r_sum": r_sum,
    #         "C_agg": C_agg
    #     }
    def pedersen_commit(self, m, r, params):
        p, g, h = params["p"], params["g"], params["h"]
        return (pow(g, m, p) * pow(h, r, p)) % p


    def generate_zk_pedersen_proof(self, z, challenge_set):
        """
        Compute m_sum, r_sum, aggregate commitment C_agg (Pedersen homomorphic),
        and a hash binding including z so cloud can't precompute final value.
        """
        p = self.ZK_PARAMS["p"]
        q = self.ZK_PARAMS["q"]

        m_sum = 0
        r_sum = 0
        C_agg = 1

        for (chunk_id, a_i) in challenge_set:
            chunk_bytes = bytes(self.file_chunks[chunk_id])
            m_i = int.from_bytes(chunk_bytes, 'big') % q
            r_i = self.random_values[chunk_id] % q
            a_i = int(a_i) % q
            # local Ci computed the same as IoT used (Pedersen)
            Ci = self.pedersen_commit(m_i, r_i, self.ZK_PARAMS)
            # Ci_hashed = int(hashlib.sha3_512(str(Ci).encode()).hexdigest(), 16) % p

            m_sum = (m_sum + (a_i * m_i)) % q
            r_sum = (r_sum + (a_i * r_i)) % q
            C_agg = (C_agg * pow(Ci, a_i, p)) % p
            print("m_i:", m_i, "r_i:", r_i, "Ci:", Ci, "m_sum:", m_sum, "r_sum:", r_sum, "C_agg:", C_agg, "Ci^a_i:", pow(Ci, a_i, p))

        # in cloud, after computing m_sum, r_sum, C_agg
        ped_check = self.pedersen_commit(m_sum % q, r_sum % q, self.ZK_PARAMS)
        # ped_check_hashed = int(hashlib.sha3_512(str(ped_check).encode()).hexdigest(), 16) % p

        if ped_check != C_agg:
            print("FATAL: Cloud-side pedersen recompute mismatch!")
            print(" ped_check:", ped_check)
            print(" C_agg   :", C_agg)
            # print per-chunk details for debugging
            for (chunk_id, a_i_raw) in challenge_set:
                a_i = int(a_i_raw) % self.ZK_PARAMS["q"]
                chunk_bytes = bytes(self.file_chunks[chunk_id])
                m_i = int.from_bytes(chunk_bytes, 'big') % self.ZK_PARAMS["q"]
                r_i = int(self.random_values[chunk_id]) % self.ZK_PARAMS["q"]
                Ci = self.pedersen_commit(m_i, r_i, self.ZK_PARAMS)
                print(f" chunk {chunk_id}: a_i={a_i}, m_i={m_i}, r_i={r_i}, Ci={Ci}, Ci^a_i={pow(Ci,a_i,self.ZK_PARAMS['p'])}")
            raise RuntimeError("Cloud pedersen recompute mismatch — aborting (see debug above)")

        # binding so cloud can't precompute independently of z
        proof_value = hashlib.sha3_256(
            str(C_agg).encode() + str(z).encode()
        ).hexdigest()

        print("p:", p, "q", q, "m_sum:", m_sum, "r_sum:", r_sum, "C_agg:", C_agg, "proof_value:", proof_value, "z: ", z)
        return {
            "m_sum": m_sum,
            "r_sum": r_sum,
            "C_agg": C_agg,
            "proof_value": proof_value
        }



    def generate_proof(self, stored_file="input.txt"):
        """Step 3: Generate storage proof (Paper's ProofGen algorithm)"""
        print("\n Generating ZK proofs for challenged chunks...")

        if not hasattr(self, "challenge_set"):
            print("   Error: Challenge not received!")
            return None
        self.file_chunks = self.read_file_chunks(stored_file)

        proof_obj = self.generate_zk_pedersen_proof(self.z, self.challenge_set)

        # self.zk_proofs = []
        # Compute the combined proof using z + challenge set
        # proof_obj = self.generate_zk_hash_proof(self.z, self.challenge_set)

        # for (chunk_id, a_i) in self.challenge_set:
        #         chunk_bytes = bytes(self.file_chunks[chunk_id])
        #         r = self.random_values[chunk_id]
        #         commitment = int(hashlib.sha3_256(chunk_bytes + r.to_bytes(8, "big")).hexdigest(), 16) % P

        #         proof = self.generate_zk_hash_proof(chunk_bytes, r, commitment, self.z, a_i)
        #         self.zk_proofs.append(proof)
        #         print(f"   Proof for chunk {chunk_id} generated.")

        # After building the merkle tree and storing all levels in self.levels
        self.aai_data = {}
        leaf_count = 1

        for chunk_id, _ in self.challenge_set:
            aai_raw = self.generate_aai(chunk_id)  # list of tuples (hash, sigma)
            aai_formatted = []
            current_leaf_count = 1

            for hash_val, sigma in aai_raw:
                aai_formatted.append({
                    "hash_value": hash_val,
                    "leaf_count": current_leaf_count,
                    "sigma": sigma
                })
                current_leaf_count *= 2

            print(f"   AAI for chunk {chunk_id}: {aai_formatted}")
            self.aai_data[str(chunk_id)] = aai_formatted

        print(f"   Generated AAI for {len(self.aai_data)} chunks")

        print(f"   Generated AAI for {len(self.aai_data)} challenged chunks")

        self.challenged_tags = {}
        for chunk_id, _ in self.challenge_set:
            self.challenged_tags[str(chunk_id)] = simple_hash(self.homomorphic_tags[chunk_id])
            print(f"   Challenged tag for chunk {chunk_id}: {self.challenged_tags[str(chunk_id)]}")

        # Include in proof
        tag_hashes = [simple_hash(str(tag)) for tag in self.homomorphic_tags]
        self.root, self.levels = self.build_merkle_tree_with_storage(tag_hashes)
        print(f"   Cloud Merkle Tree built successfully.")
        self.proof = {
            #"quotient_polynomial": self.quotient_poly,
            "aai_data": self.aai_data,
            #"proof_poly_at_z": self.proof_poly_at_z,
            "challenge_metadata": {
                "challenge_set": self.challenge_set,
                "z": self.z,
                "k1": self.k1,
                "k2": self.k2,
                "c": self.c
            },
            "challenged_tags": self.challenged_tags,
            "homomorphic_tags": self.homomorphic_tags,
            #"B": self.B,
            "zk_proofs": proof_obj,
            "cloud_root_hash": self.root
        }

        return self.proof
    
 
    def build_merkle_tree_with_storage(self, leaf_hashes):
        """
        Builds the Merkle tree and stores the nodes at all levels.
        Returns:
            root hash,
            levels: a list where levels[0] is leaves, levels[-1] is root level
        """
        levels = [leaf_hashes]
        level = leaf_hashes
        z = 1
        while len(level) > 1:
            next_level = []
            z *= 2
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                parent = simple_hash(f"{z}||{left}||{right}")
                next_level.append(parent)
                print(f"   h({z}||{left}||{right}) = {parent}")
            levels.append(next_level)
            level = next_level
        return levels[-1][0], levels

    def generate_aai(self, leaf_index):
        """
        Computes the auxiliary authentication information (AAI) for leaf_index.
        Returns a list of tuples (hash, direction) starting from leaf level upwards.
        direction: 0 if sibling is left child, 1 if right child
        """
        tag_hashes = []
        for i, tag in enumerate(self.homomorphic_tags):
            tag_hash = simple_hash(tag)
            tag_hashes.append(tag_hash)
            print(f"   h(ϖ{i}) = {tag_hash}")

        self.root, self.levels = self.build_merkle_tree_with_storage(tag_hashes)
        if not hasattr(self, 'levels'):
            raise Exception("Tree levels not built yet")
        
        aai_list = []
        index = leaf_index
        for level in self.levels[:-1]:  # exclude root
            sibling_index = index ^ 1
            if sibling_index >= len(level):
                sibling_index = index  # duplicate if no sibling
            sibling_hash = level[sibling_index]
            direction = 0 if sibling_index < index else 1  # left or right sibling
            aai_list.append((sibling_hash, direction))
            index = index // 2
        return aai_list

    def send_proof_to_verifier(self, filename="cloud_to_verifier.enc.json"):
        """STEP 4: Send post-quantum hash-based proof to Verifier"""
        print(f"\n STEP 4: Sending Post-Quantum Hash-Based Proof to Verifier")

        if not hasattr(self, 'proof'):
            print("   Error: No proof generated! Run generate_proof() first.")
            return False

        # Build the verifier-facing proof package
        proof_package = {
            "zk_proofs": self.proof.get("zk_proofs", []),
            "challenge_metadata": self.proof.get("challenge_metadata", {}),
            "aai_data": self.proof.get("aai_data", {}),
            "challenged_tags": self.proof.get("challenged_tags", {}),
            "cloud_root_hash": self.proof.get("cloud_root_hash", {})
        }

        # Convert to bytes for encryption
        proof_json = json.dumps(proof_package, indent=2).encode()

        # Encrypt with server PQ-KEM (same as IoT->cloud encryption)
        if not os.path.exists(SERVER_KEM_PUB):
            raise FileNotFoundError(f"Server public key not found: {SERVER_KEM_PUB}. Run `python3 config.py` to generate keys or copy server key.")
        
        with open(SERVER_KEM_PUB, "r") as f:
            server_pk = base64.b64decode(f.read().strip())

        ct, shared = kem_encapsulate(server_pk)
        proof_encrypted_payload = encrypt_with_shared_key(shared, proof_json)

        # Final JSON (base64-encoded ciphertext + encapsulated key)
        proof_out_obj = {
            "ct": base64.b64encode(ct).decode(),
            "enc_payload": base64.b64encode(proof_encrypted_payload).decode()
        }

        # Write encrypted proof file for verifier
        with open(filename, "w") as f:
            json.dump(proof_out_obj, f, indent=2)

        # ✅ Logging summary
        cm = proof_package.get("challenge_metadata", {})
        z_value = cm.get("z", "N/A")
        print(f"   ✔ Proof encrypted and written to: {filename}")
        print(f"   ✔ ZK proofs sent: {len(proof_package['zk_proofs'])}")
        print(f"   ✔ Challenge z: {z_value}")
        print(f"   ✔ AAI entries: {len(proof_package['aai_data'])}")
        print(f"   ✔ Tags included: {len(proof_package['challenged_tags'])}")

        return True


    def run_complete_workflow(self):
        """Execute complete cloud server workflow"""
        print("=" * 60)
        print(" Cloud Server - Storage Verification System")
        print(" Following Paper's ProofGen Algorithm")
        print("=" * 60)
        
        try:
            # Pre-step: if encrypted payload exists try to decrypt it and write iot_to_cloud.json
            if os.path.exists("iot_to_cloud.enc.json"):
                if not self.decrypt_iot_payload():
                    return False
            else:
                print("   No encrypted payload found; will attempt to load iot_to_cloud.json directly.")


            # Step 1: Load data from IoT
            if not self.load_data_from_iot():
                return False
            

            # Step 2: Receive challenge (simulate from verifier)
            challenge_set = self.receive_challenge(filename="challenge.json")  # Small challenge
            if not challenge_set:
                return False
            
            # Step 3: Generate proof
            proof = self.generate_proof("input.txt")
            if not proof:
                return False
            
            # Step 4: Send proof to verifier
            if not self.send_proof_to_verifier():
                return False
            
            print("\n Cloud Server Workflow Completed Successfully!")
            print("=" * 60)
            print(f" Summary:")
            print(f"   • Challenge received: {len(self.challenge_set)} chunks challenged")
            print(f"   • Proof generated: quotient polynomial + AAI")
            print(f"   • Ready for verifier to check integrity!")
            
            return True
            
        except Exception as e:
            print(f"\n Error in cloud server workflow: {e}")
            return False

def main():
    """Main function"""
    print("Starting Simple Cloud Server Simulation...")
    
    # Run cloud server
    server = SimpleCloudServer()
    success = server.run_complete_workflow()
    
    if success:
        print("\n Ready for verifier to check the proof!")
    else:
        print("\n Cloud server failed!")

if __name__ == "__main__":
    main()