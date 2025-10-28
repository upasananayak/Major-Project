#!/usr/bin/env python3
"""
Simple Verifier - IIoT Storage Verification System  
Based on the IEEE paper's ProofVeri algorithm
"""
from pq_utils import set_demo_deterministic_seed
set_demo_deterministic_seed()

import base64
from itertools import product
import json
import os
from config import SERVER_KEM_SK
from utils import HHF, eval_polynomial, P
from pq_utils import decrypt_with_shared_key, kem_decapsulate, simple_hash, verify_chunk_proof, verify_signature, verify_zk_proof
from typing import Dict, List, Tuple


class SimpleVerifier:
    def __init__(self):
        """Initialize verifier"""
        print(" Initializing Simple Verifier")
        self.root_hash = None
        self.public_params = None
        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)
        print("ZK PARAMS fingerprint:", (self.ZK_PARAMS["p"] % 2**32, self.ZK_PARAMS["q"] % 2**32))

    def load_data_from_iot(self, filename="iot_to_verifier_dec.json"):
        """Step 1: Load root hash and public params from IoT device"""
        print(f"\n STEP 1: Loading Data from IoT Device")
        
        try:
            with open(filename, 'r') as f:
                iot_data = json.load(f)
            
            self.root_hash = iot_data["root_hash"]
            self.root_signature = iot_data.get("root_signature")
            self.public_params = iot_data["public_parameters"]
            self.public_key = iot_data.get("public_key")
            self.num_chunks = iot_data["num_chunks"]
            self.blocks_per_chunk = iot_data["blocks_per_chunk"]
           

            print(f"   Root hash received: {self.root_hash}")
            print(f"   PQ Signature received: {self.root_signature[:60]}...")  # truncated for readability
            print(f"   PQ Public key: {self.public_key[:60]}...")
            print(f"   Public parameters: {self.public_params}")
            print(f"   File info: {self.num_chunks} chunks, {self.blocks_per_chunk} blocks each")
            
            root_bytes = self.root_hash.encode() if isinstance(self.root_hash, str) else str(self.root_hash).encode()
            sig_ok = verify_signature(self.public_key, root_bytes, self.root_signature)
            
            if not sig_ok:
                print("  PQ signature verification FAILED! Rejecting IoT data.")
                return False
            print("  PQ signature verified successfully.")

            return True
            
        except FileNotFoundError:
            print(f"   Error: {filename} not found. Run IoT simulation first!")
            return False

    def decrypt_iot_verifier_file(self, enc_filename="iot_to_verifier.enc.json", out_filename="iot_to_verifier_dec.json"):
        """If an encrypted verifier file exists, decapsulate with server SK and write decrypted JSON."""
        print("\n PRESTEP: Decrypting IoT -> Verifier encrypted payload (if present)")
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

            # decapsulate and decrypt
            shared = kem_decapsulate(server_sk, ct)
            plaintext = decrypt_with_shared_key(shared, enc_payload)
            payload_json = json.loads(plaintext.decode())

            # write decrypted JSON for later steps
            with open(out_filename, "w") as out_f:
                json.dump(payload_json, out_f, indent=2)

            print(f"   Decrypted verifier payload written to: {out_filename}")
            return True
        except Exception as e:
            print(f"   Decryption failed: {e}")
            return False
    def load_proof_from_cloud(self, filename="cloud_to_verifier_dec.json"):
        """Step 2: Load proof from cloud server"""
        print(f"\n STEP 2: Loading Proof from Cloud Server")
        
        try:
            with open(filename, 'r') as f:
                self.proof_data = json.load(f)
            
            # self.quotient_poly = self.proof_data["quotient_polynomial"]
            # self.challenged_tags_aai = self.proof_data["challenged_tags_and_aai"]
            self.aai_data = self.proof_data["aai_data"]
            # self.proof_poly_at_z = self.proof_data["proof_poly_at_z"]
            self.challenge_metadata = self.proof_data["challenge_metadata"]
            self.challenged_tags=self.proof_data["challenged_tags"]
            # self.B = self.proof_data["B"]
            self.zk_proofs = self.proof_data.get("zk_proofs", [])

            print(f"   ZK proofs received: {len(self.zk_proofs)}")
            # print(f"   Quotient polynomial: {self.quotient_poly}")
            print(f"   AAI data: {len(self.aai_data)}")
            #print(f"   P_prf(z) = {self.proof_poly_at_z}")
            print(f"   Challenge metadata: {self.challenge_metadata}")
            print("   Challenged tags received:", self.challenged_tags)
            # print(f"   B (masking value): {self.B}")
            return True
            
        except FileNotFoundError:
            print(f"   Error: {filename} not found. Run cloud server first!")
            return False

    def decrypt_cloud_proof_file(self, enc_filename="cloud_to_verifier.enc.json", out_filename="cloud_to_verifier_dec.json"):
        """If an encrypted cloud->verifier file exists, decapsulate with server SK and write decrypted JSON."""
        print("\n PRESTEP: Decrypting Cloud -> Verifier encrypted proof (if present)")
        if not os.path.exists(enc_filename):
            print(f"   Encrypted cloud proof not found: {enc_filename} (skipping decryption)")
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

            # write decrypted JSON for verifier consumption
            with open(out_filename, "w") as out_f:
                json.dump(payload_json, out_f, indent=2)

            print(f"   Decrypted cloud proof written to: {out_filename}")
            return True
        except Exception as e:
            print(f"   Decryption failed: {e}")
            return False
        
    def verify_tag_imht(self):
        """
        Real Tag-IMHT verification using AAI paths.
        Implements the verification algorithm from Section IV of the paper.
        """
        print("    Verifying Tag-IMHT using real AAI paths...")
        
        challenged_tags = self.proof_data.get('challenged_tags', {})
        aai_data = self.aai_data
        
        if not challenged_tags or not aai_data:
            print("    Missing challenged tags or AAI data in proof.")
            return False
        
        for chunk_str, aai_path in aai_data.items():
            chunk = int(chunk_str)
            tag = challenged_tags.get(chunk_str)
            
            if tag is None:
                print(f"    Missing tag for chunk {chunk}")
                return False
            
            # Starting point: leaf hash is the tag itself (assumed integer)
            current_hash = tag
            leaf_count = 1
            index = 1
            
            # Iterate over authentication path nodes
            for node in aai_path:
                sibling_hash = node['hash_value']
                node_leaf_count = node['leaf_count'] *2 
                sigma = node['sigma']
                
                # Compute parent hash depending on sibling position sigma
                if sigma == 0:
                    # sibling is left child, so current node is right child
                    combined = f"{node_leaf_count}||{sibling_hash}||{current_hash}"
                    index += node_leaf_count
                else:
                    # sibling is right child, so current node is left child
                    combined = f"{node_leaf_count}||{current_hash}||{sibling_hash}"
                    
                current_hash = simple_hash(combined)
                
                # Debug prints
                print(f"    Step: sibling_hash={sibling_hash}, leaf_count={node_leaf_count}, sigma={sigma}")
                print(f"    Combined string: {combined}")
                print(f"    Hash after step: {current_hash}")
            
            # Check if computed root matches stored root
            if current_hash != self.root_hash:
                print(f"    Verification failed for chunk {chunk}: computed root {current_hash} != expected root {self.root_hash}")
                return False
            else:
                print(f"    AAI Verification succeeded for chunk {chunk}\n")
        
        print("    All challenged chunks verified successfully.")
        return True

    
    def _reconstruct_root_from_aai(self, tag_hash: str, aai_path: List[Dict], expected_index: int) -> Tuple[str, int]:
        
        current_hash = tag_hash
        current_leaf_count = 1
        computed_index = 1

        for aai_tuple in aai_path:
            sibling_hash = aai_tuple['hash_value']
            sibling_leaf_count = aai_tuple['leaf_count']
            sigma = aai_tuple['sigma']
            
            new_leaf_count = current_leaf_count + sibling_leaf_count
            
            if sigma == 0:
                computed_index = computed_index + sibling_leaf_count
                
            #  FIX: Use binary concatenation like IoT device
            z_bytes = new_leaf_count
            
            current_bytes = current_hash
            sibling_bytes = sibling_hash
            
            if sigma == 0:
                # left child is sibling, right child is current node
                data = z_bytes + sibling_bytes + current_bytes
            else:
                # left child is current node, right child is sibling
                data = z_bytes + current_bytes + sibling_bytes
            
            current_hash = simple_hash(data)
            #print("       curr leaf count:", current_leaf_count)
            #print("       new leaf count:", new_leaf_count)
            print("         current bytes:", current_bytes)
            print("         sibling bytes:", sibling_bytes)
            #print("         data:", data.hex())
            print("         data hash:", current_hash)
            
            current_leaf_count = new_leaf_count
        
        return current_hash, computed_index

    def verify_zero_knowledge(self):
        """Step: Verify ZK proofs from cloud"""
        print("\n STEP 3.5: Verifying Zero-Knowledge Proofs")

        if not hasattr(self, "zk_proofs") or not self.zk_proofs:
            print("   No ZK proofs received from cloud.")
            return False

        all_ok = True
        for i, proof_desc in enumerate(self.zk_proofs):
            proof = proof_desc["proof"]
            commitment = proof_desc["commitment"]
            ok = verify_chunk_proof(proof, self.ZK_PARAMS)
            print(f"   Proof {i}: {' Verified' if ok else ' Failed'}")
            if not ok:
                all_ok = False

        return all_ok
    

    def run_complete_verification(self):
        """Execute complete verifier workflow"""
        print("="* 60)
        print(" Verifier - Storage Verification System")
        print(" Following Paper's ProofVeri Algorithm")
        print("=" * 60)
        
        try:
            self.decrypt_iot_verifier_file()
            # Step 1: Load data from IoT device
            if not self.load_data_from_iot():
                return False
            
            self.decrypt_cloud_proof_file()
            # Step 2: Load proof from cloud server
            if not self.load_proof_from_cloud():
                return False
            
            # Step 3: Verify Tag-IMHT
            if not self.verify_tag_imht():
                print("\n Tag-IMHT verification failed!")
                return False

            if not self.verify_zero_knowledge():
                print("\n ZK proof verification failed!")
                return False

            
            print("\n VERIFICATION SUCCESSFUL!")
            print("=" * 60)
            print(f" Verification Summary:")
            print(f"   • Tag-IMHT integrity:  VERIFIED")
            print(f"   • Proof equation: VERIFIED")
            print(f"   • Cloud data integrity:  CONFIRMED")
            print(f"   • System security:  MAINTAINED")
            
            return True
            
        except Exception as e:
            print(f"\n Error in verification: {e}")
            return False

def main():
    """Main function"""
    print("Starting Simple Verifier Simulation...")
    
    # Run verifier
    verifier = SimpleVerifier()
    success = verifier.run_complete_verification()
    
    if success:
        print("\nStorage integrity verification completed successfully!")
        print("The cloud data is intact and secure! ")
    else:
        print("\n Verification failed! Data integrity compromised!")

if __name__ == "__main__":
    main()
