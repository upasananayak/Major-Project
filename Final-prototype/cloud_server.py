#!/usr/bin/env python3
"""
Simple Cloud Server - IIoT Storage Verification System
Based on the IEEE paper's ProofGen algorithm
"""
from pq_utils import set_demo_deterministic_seed
set_demo_deterministic_seed()

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


    def load_data_from_iot(self, filename="iot_to_cloud_dec.json"):
        """Step 1: Load data uploaded by IoT device"""
        print(f"\n STEP 1: Loading Data from IoT Device")
        
        try:
            with open(filename, 'r') as f:
                self.stored_data = json.load(f)
            
            self.file_chunks = self.stored_data["file_chunks"]
            self.homomorphic_tags = self.stored_data["homomorphic_tags"]
            self.polynomial_commitments = self.stored_data["polynomial_commitments"]
            self.metadata = self.stored_data["metadata"]
            
            print(f"   Loaded {len(self.file_chunks)} file chunks")
            print(f"   Loaded {len(self.homomorphic_tags)} homomorphic tags")
            print(f"   Metadata: {self.metadata}")
            
            self.received_data = True
            return True
            
        except FileNotFoundError:
            print(f"   Error: {filename} not found. Run IoT simulation first!")
            return False
        
    def pedersen_commit(self, m, r, params):
        p, g, h = params["p"], params["g"], params["h"]
        return (pow(g, m, p) * pow(h, r, p)) % p


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
        
    def receive_challenge(self, k1=42, k2=17, c=2, filename = "chalenge.json"):
        """Step 2: Receive challenge from verifier (Paper's Chal algorithm)"""
        print(f"\n STEP 2: Receiving Challenge from Verifier")
        
        if not self.received_data:
            print("   Error: No data received from IoT device!")
            return None
     
        if filename:
            with open(filename, 'r') as f:
                self.stored_data = json.load(f)

            self.k1 = self.stored_data["k1"]
            self.k2 = self.stored_data["k2"]
            self.c = self.stored_data["c"]
            
            print(f"   Loaded k1={self.k1}, k2={self.k2}, c={self.c} from {filename}")
           
        else:
            print(f"   Using provided k1={k1}, k2={k2}, c={c}")
            # Store challenge parameters (from paper's Chal algorithm)
            self.k1 = k1  # Random key for pseudo-random permutation
            self.k2 = k2  # Random key for pseudo-random function  
            self.c = c    # Number of challenged file chunks

        print(f"   Challenge parameters: k1={self.k1}, k2={self.k2}, c={self.c}")

        # Generate challenge set S = {(id, a_id)} (Paper equation)
        self.challenge_set = []
        for l in range(1, self.c + 1):
            # id ← π_k1(l) - index of challenged chunk
            chunk_id = pseudo_random_permutation(self.k1, l) % len(self.file_chunks)
            # a_id ← f_k2(l) - coefficient for proof generation
            coefficient = pseudo_random_function(self.k2, l)

            self.challenge_set.append((chunk_id, coefficient))
        
        print(f"   Challenge set S: {self.challenge_set}")
        
        # Generate random value z for polynomial commitment (Paper)
        self.z = pseudo_random_function(self.k2, self.c + 1)
        print(f"   Random z for polynomial commitment: {self.z}")
        
        return self.challenge_set

    def generate_proof(self):
        """Step 3: Generate storage proof (Paper's ProofGen algorithm)"""
        print("\n Generating ZK proofs for challenged chunks...")

        self.zk_proofs = []
        self.proof = None

        for (chunk_id, _) in self.challenge_set:
            commit_data = self.polynomial_commitments[chunk_id]

            # Extract stored values
            stored_commit = int(commit_data["commitment"])
            r = int(commit_data["r"])
            coeffs = commit_data["coeffs"]

            # 1) Compute polynomial value in two ways:
            poly_value_hash_field = int(eval_polynomial(coeffs, PSI, P))  # old hash scheme used P
            poly_value_ped = int(eval_polynomial(coeffs, PSI, self.ZK_PARAMS["q"])) % self.ZK_PARAMS["q"]

            # 2) Recompute the old hash commitment (sha3_256) to detect legacy commitments
            data = f"{poly_value_hash_field}|{r}".encode()
            recomputed_hash = int(hashlib.sha3_256(data).hexdigest(), 16) % P

            if recomputed_hash == stored_commit:
                # Detected legacy hash-based commitment. Migrate this single commitment to Pedersen.
                new_ped = self.pedersen_commit(poly_value_ped, r, self.ZK_PARAMS)
                print(f"  Detected legacy hash commitment for chunk {chunk_id} -> migrating to Pedersen.")
                print(f"    old (hash) = {stored_commit}")
                print(f"    new (ped)  = {new_ped}")

                # Update in-memory structure so prover uses Pedersen commitment
                commit_data["commitment"] = int(new_ped)

                # Persist the migration back to the IoT->Cloud JSON file so future runs are consistent
                try:
                    IoT_FILE = "iot_to_cloud_dec.json"  # adjust if your file has a different name
                    with open(IoT_FILE, "r") as f:
                        iot_data = json.load(f)

                    # defensive checks & update
                    if "polynomial_commitments" in iot_data and len(iot_data["polynomial_commitments"]) > chunk_id:
                        iot_data["polynomial_commitments"][chunk_id]["commitment"] = int(new_ped)
                    else:
                        # fallback: try top-level list path that some versions use
                        raise KeyError("polynomial_commitments not found or chunk_id out of range in IoT file")

                    # write back (atomic-ish: write to tmp then rename is better, but this is fine for demo)
                    with open(IoT_FILE, "w") as f:
                        json.dump(iot_data, f, indent=2)
                    print(f"    Persisted migrated commitment to {IoT_FILE}")
                except Exception as e:
                    print(f"    ERROR: Could not persist migrated commitment to disk: {e}")
                    # still continue in-memory so current run can proceed

            else:
                # If stored_commit equals Pedersen already, or neither matches, proceed but keep diagnostic prints
                # compute pedersen recomputed to compare (diagnostic)
                ped_recomputed = self.pedersen_commit(poly_value_ped, r, self.ZK_PARAMS)
                if ped_recomputed != stored_commit:
                    # If neither matches it's probably a params or r mismatch — fail early with diagnostics
                    print(f"  Commitment mismatch for chunk {chunk_id}:")
                    print(f"    stored_commit : {stored_commit}")
                    print(f"    recomputed hash: {recomputed_hash}")
                    print(f"    recomputed ped : {ped_recomputed}")
                    raise ValueError("Commitment mismatch: stored commitment does not match hash or pedersen recomputation.")

            # Now commit_data carries a Pedersen commitment; generate ZK proof using existing wrapper
            proof = prove_chunk(commit_data, PSI, self.ZK_PARAMS)

            # store proof (send to verifier later). Keep commitment for verifier reference too.
            self.zk_proofs.append({
                "chunk_id": chunk_id,
                "commitment": commit_data["commitment"],
                "proof": proof
            })
            print(f"   Chunk {chunk_id}: ZK proof generated.")



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
            "zk_proofs": self.zk_proofs
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
        """Step 4: Send proof to verifier"""
        print(f"\n STEP 4: Sending Proof to Verifier")
        
        if not hasattr(self, 'proof'):
            print("   Error: No proof generated!")
            return False
        
        proof_json = json.dumps(self.proof).encode()
        if not os.path.exists(SERVER_KEM_PUB):
            raise FileNotFoundError(f"Server public key not found: {SERVER_KEM_PUB}. Run `python3 config.py` to generate keys or copy server key.")
        with open(SERVER_KEM_PUB, "r") as f:
            server_pk = base64.b64decode(f.read().strip())

        ct, shared = kem_encapsulate(server_pk)
        proof_encrypted_payload = encrypt_with_shared_key(shared, proof_json)

                # Save ct and encrypted payload as base64 JSON fields (deterministic parsing)
        proof_out_obj = {
            "ct": base64.b64encode(ct).decode(),
            "enc_payload": base64.b64encode(proof_encrypted_payload).decode()
        }

        # Save proof to file
        with open(filename, 'w') as f:
            json.dump(proof_out_obj, f, indent=2)
        
        print(f"   Proof sent to verifier: {filename}")
        print(f"   Proof contains: quotient polynomial, {len(self.aai_data)} challenged tags")
        
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
            challenge_set = self.receive_challenge(k1=42, k2=17, c=3, filename="challenge.json")  # Small challenge
            if not challenge_set:
                return False
            
            # Step 3: Generate proof
            proof = self.generate_proof()
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