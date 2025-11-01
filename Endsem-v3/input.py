
#!/usr/bin/env python3
"""
Simple Verifier - IIoT Storage Verification System  
Based on the IEEE paper's ProofVeri algorithm
"""
# from pq_utils import set_demo_deterministic_seed
# set_demo_deterministic_seed()

import base64
import hashlib
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
        # self.public_params = None
        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)
        print("ZK PARAMS fingerprint:", (self.ZK_PARAMS["p"] % 2**32, self.ZK_PARAMS["q"] % 2**32))
        # ADD THIS BLOCK (paste into IoT, Cloud, and Verifier startup)
        with open("zk_params.json", "r") as _f:
            zk = json.load(_f)
        print("ZK PARAMS check: p,q (truncated):", zk["p"] % 2**64, zk["q"] % 2**64)
        print("ZK PARAMS check: g,h (truncated):", int(zk["g"]) % 2**64, int(zk["h"]) % 2**64)
        # optional assert to fail fast if mismatch:
        assert hasattr(self, "ZK_PARAMS") and self.ZK_PARAMS["p"] == zk["p"] and self.ZK_PARAMS["g"] == zk["g"] and self.ZK_PARAMS["h"] == zk["h"], "ZK_PARAMS mismatch! Make sure zk_params.json is the same for Verifier"


    def load_data_from_iot(self, filename="iot_to_verifier_dec.json"):
        """Step 1: Load root hash and public params from IoT device"""
        print(f"\n STEP 1: Loading Data from IoT Device")
        
        try:
            with open(filename, 'r') as f:
                iot_data = json.load(f)
            
            self.root_hash = iot_data["root_hash"]
            self.root_signature = iot_data.get("root_signature")
            # self.public_params = iot_data["public_parameters"]
            self.public_key = iot_data.get("public_key")
            self.num_chunks = iot_data["num_chunks"]
            self.blocks_per_chunk = iot_data["blocks_per_chunk"]
            self.commitments = iot_data["commitments"]
           

            print(f"   Root hash received: {self.root_hash}")
            print(f"   PQ Signature received: {self.root_signature[:60]}...")  # truncated for readability
            print(f"   PQ Public key: {self.public_key[:60]}...")
            # print(f"   Public parameters: {self.public_params}")
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
            self.cloud_root_hash = self.proof_data.get("cloud_root_hash")

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


    # def verify_zero_knowledge(self):
    #     """STEP 3.5: Verify post-quantum hash-based proofs from Cloud"""
    #     print("\n STEP 3.5: Verifying Post-Quantum Hash-Based Proofs")

    #     if not hasattr(self, "zk_proofs") or not self.zk_proofs:
    #         print("   No ZK proofs received from cloud.")
    #         return False

    #     if "z" not in self.challenge_metadata:
    #         print("❌ Challenge metadata missing 'z'. Cannot verify.")
    #         return False

    #     z = self.challenge_metadata["z"]
    #     print(f"   Using challenge z = {z}")

    #     # ✅ Load IoT commitments for integrity cross-check
    #     try:
    #         with open("iot_to_verifier_dec.json", "r") as f:
    #             iot_data = json.load(f)
    #         original_commitments = iot_data["commitments"]
    #         print(f"   Loaded {len(original_commitments)} original commitments from IoT.")
    #     except Exception as e:
    #         print(f"❌ Failed to load IoT commitments: {e}")
    #         return False

    #     all_ok = True

    #     # --- Each proof corresponds to a chunk_id in the challenge set ---
    #     challenge_set = self.challenge_metadata.get("challenge_set", [])
    #     for i, (chunk_id, a_i) in enumerate(challenge_set):
    #         if i >= len(self.zk_proofs):
    #             print(f"❌ Missing proof for chunk {chunk_id}")
    #             all_ok = False
    #             continue

    #         proof = self.zk_proofs[i]
    #         proof_commitment = proof["commitment"]

    #         # --- Step 1: Check IoT binding ---
    #         try:
    #             expected_commitment = original_commitments[chunk_id]
    #         except IndexError:
    #             print(f"❌ Invalid chunk_id {chunk_id} in proof metadata.")
    #             all_ok = False
    #             continue

    #         if proof_commitment != expected_commitment:
    #             print(f"❌ Commitment mismatch for chunk {chunk_id}")
    #             print(f"   Expected: {expected_commitment}")
    #             print(f"   Got:      {proof_commitment}")
    #             all_ok = False
    #             continue

    #         # --- Step 2: Normal ZK proof verification ---
    #         ok = self.verify_zk_hash_proof(proof, z)
    #         print(f"   Proof for chunk {chunk_id}: {'✅ Verified' if ok else '❌ Failed'}")
    #         if not ok:
    #             all_ok = False

    #     if all_ok:
    #         print("\n✅ All post-quantum hash-based proofs verified successfully and match IoT commitments!")
    #     else:
    #         print("\n❌ Some proofs failed or commitments mismatched — data may be tampered.")

    #     return all_ok
    # def verify_zero_knowledge(self):
    #     """STEP 3.5: Verify challenge-dependent ZK proof"""
    #     print("\n STEP 3.5: Verifying challenge-dependent ZK proof")

    #     if not hasattr(self, "zk_proofs"):
    #         self.zk_proofs = self.proof_data.get("zk_proofs")
    #     if not self.zk_proofs:
    #         print("❌ Missing zk_proofs in received data.")
    #         return False

    #     z = self.challenge_metadata["z"]
    #     challenge_set = self.challenge_metadata["challenge_set"]
    #     P = self.ZK_PARAMS["p"] % 2**32  # or whatever modulus you’re using

    #     try:
    #         with open("iot_to_verifier_dec.json", "r") as f:
    #             iot_data = json.load(f)
    #         commitments = iot_data["commitments"]
    #         print(f"   Loaded {len(commitments)} commitments from IoT.")
    #     except Exception as e:
    #         print(f"❌ Failed to load IoT commitments: {e}")
    #         return False

    #     # Recompute m_sum and r_sum using IoT commitments for consistency
    #     # (Note: the verifier doesn't know r_i, so can only check hash binding)
    #     proof_value = self.zk_proofs["proof_value"]
    #     m_sum = self.zk_proofs["m_sum"]
    #     r_sum = self.zk_proofs["r_sum"]

    #     # Recompute expected hash
    #     recomputed_hash = hashlib.sha3_256(
    #         str(m_sum).encode() + str(r_sum).encode() + str(z).encode()
    #     ).hexdigest()

    #     if recomputed_hash != proof_value:
    #         print("❌ ZK proof hash mismatch! Possible tampering.")
    #         return False

    #     print("✅ ZK proof verified successfully — challenge was satisfied.")
    #     return True

    # def verify_zero_knowledge(self):
    #     print("\n STEP 3.5: Verifying challenge-dependent ZK proof")

    #     proof = self.zk_proofs
    #     z = self.challenge_metadata["z"]
    #     challenge_set = self.challenge_metadata["challenge_set"]
    #     P = self.ZK_PARAMS["p"]

    #     with open("iot_to_verifier_dec.json", "r") as f:
    #         iot_data = json.load(f)
    #     commitments = iot_data["commitments"]

    #     print("commitments ",commitments )
    #     # 1️⃣ Recompute aggregated commitment from IoT commitments and challenge
    #     C_agg_expected = 1
    #     for (chunk_id, a_i) in challenge_set:
    #         C_agg_expected = (C_agg_expected * pow(commitments[chunk_id], a_i, P)) % P

    #     # 2️⃣ Check that hash of (m_sum, r_sum) equals C_agg_expected
    #     m_sum = proof["m_sum"]
    #     r_sum = proof["r_sum"]
    #     C_agg = proof["C_agg"]

    #     print("Expected C_agg:", C_agg_expected)
    #     m_sum_bytes = m_sum.to_bytes((m_sum.bit_length() + 7) // 8, "big")
    #     r_sum_bytes = r_sum.to_bytes(8, "big")  # same 8 bytes as IoT uses for r_i
        
    #     recomputed_commitment = int(
    #         hashlib.sha3_256(m_sum_bytes + r_sum_bytes).hexdigest(), 16
    #     ) % P


    #     print("Received C_agg:", C_agg)
    #     print("Recomputed commitment from (m_sum, r_sum):", recomputed_commitment)
    #     if recomputed_commitment != C_agg_expected:
    #         print("❌ Proof failed — mismatch between commitments and aggregated proof.")
    #         return False

    #     print("✅ ZK proof verified — cloud used correct chunks for this challenge.")
    #     return True

    # Add to the Verifier class (verifier.py)
    def pedersen_commit(self, m, r, params):
        p, g, h = params["p"], params["g"], params["h"]
        return (pow(g, m, p) * pow(h, r, p)) % p

    def verify_zero_knowledge(self):
        print("\n STEP 3.5: Verifying Pedersen challenge-dependent proof")

        proof = self.proof_data.get("zk_proofs", None)
        if not proof:
            print("❌ No proof data")
            return False

        z = self.challenge_metadata["z"]
        challenge_set = self.challenge_metadata["challenge_set"]
        p = self.ZK_PARAMS["p"]
        q = self.ZK_PARAMS["q"]

        print("p:", p, "q", q, "z:", z)
        print("proof:", proof)
        # with open("iot_to_verifier_dec.json", "r") as f:
        #     iot = json.load(f)
        commitments = self.commitments
        print("commitments:", commitments)
        # 1) aggregated commitments
        C_agg_expected = 1
        for (chunk_id, a_i) in challenge_set:
            a_i = int(a_i) % q
            # Ci_hashed = int(hashlib.sha3_512(str(commitments[chunk_id]).encode()).hexdigest(), 16) % p
            # C_agg_expected = (C_agg_expected * pow(Ci_hashed, a_i, p)) % p

            C_agg_expected = (C_agg_expected * pow(commitments[chunk_id], a_i, p)) % p
            print("  chunk_id:", chunk_id, "a_i:", a_i, "commitment:", commitments[chunk_id], "C_agg_expected:", C_agg_expected)

        # 2) pedersen recomputed from m_sum and r_sum
        m_sum = proof["m_sum"] % q
        r_sum = proof["r_sum"] % q

        print("m_sum:", m_sum, "r_sum:", r_sum)
        ped_recomputed = self.pedersen_commit(m_sum, r_sum, self.ZK_PARAMS)
        # ped_recomputed_hashed = int(hashlib.sha3_512(str(ped_recomputed).encode()).hexdigest(), 16) % p
        print("ped_recomp: ", ped_recomputed)
        # 3) Check binding value (proof_value) ties the cloud's aggregation to z
        expected_binding = hashlib.sha3_256(
            str(proof["C_agg"]).encode() + str(z).encode()
        ).hexdigest()
        print("expected_binding:", expected_binding, "proof_value:", proof["proof_value"], "z:", z)

        print("VERIFIER DIAGNOSTICS:")
        print(" p:", p)
        print(" q:", q)
        print(" g (trunc):", int(self.ZK_PARAMS['g']) % 2**64)
        print(" h (trunc):", int(self.ZK_PARAMS['h']) % 2**64)
        print("challenge_set:", challenge_set)
        print("m_sum (from proof):", m_sum)
        print("r_sum (from proof):", r_sum)
        print("C_agg (from proof):", proof["C_agg"])
        print("C_agg_expected:", C_agg_expected)
        print("ped_recomputed (g^m_sum * h^r_sum % p):", ped_recomputed)

        # Also compute ratio = C_agg_expected * inv(ped_recomputed) % p to see difference
        inv_ped = pow(ped_recomputed, -1, p)
        ratio = (C_agg_expected * inv_ped) % p
        print("ratio (C_agg_expected / ped_recomputed mod p):", ratio)

        if ped_recomputed != C_agg_expected:
            print("❌ Proof failed — recomputed Pedersen(commit(m_sum,r_sum)) != aggregated commitments")
            print("expected:", C_agg_expected)
            print("got (ped):", ped_recomputed)
            return False

        
        if expected_binding != proof["proof_value"]:
            print("❌ Proof binding mismatch (cloud did not include z correctly)")
            return False

        print("✅ ZK Pedersen-style proof verified successfully.")
        return True

    # def verify_zk_hash_proof(self, proof, z):
    #     """Verify post-quantum hash-based zero-knowledge proof."""
    #     try:
    #         commitment = proof["commitment"]
    #         a_i = proof["a_i"]
    #         c_i = bytes.fromhex(proof["c_i"])
    #         R = proof["R"]
    #     except KeyError as e:
    #         print(f"❌ Missing key in proof: {e}")
    #         return False

    #     # Step 1: Recompute Fiat–Shamir challenge
    #     recomputed_c_i = hashlib.sha3_256(
    #         str(commitment).encode() + str(z).encode() + str(a_i).encode()
    #     ).digest()

    #     if recomputed_c_i != c_i:
    #         print("❌ Challenge mismatch in proof")
    #         return False

    #     # Step 2: Check deterministic binding of R to (commitment, c_i)
    #     expected_R = hashlib.sha3_256(c_i + str(commitment).encode()).hexdigest()
    #     if R != expected_R:
    #         print(f"❌ Inconsistent proof hash binding for commitment: {commitment}")
    #         return False

    #     return True

    def verify_root_consistency(self):
        """Cross-verify IoT and Cloud Merkle roots."""
        print("\n STEP 3.4: Verifying Merkle Root Consistency (IoT vs Cloud)")

        iot_root = self.root_hash
        # cloud_root = self.proof_data.get("cloud_root_hash")

        if not self.cloud_root_hash:
            print("❌ Cloud proof missing Merkle root!")
            return False

        print(f"   IoT root:   {iot_root}")
        print(f"   Cloud root: {self.cloud_root_hash}")

        if iot_root != self.cloud_root_hash:
            print("❌ Merkle root mismatch! Cloud data has been modified.")
            return False

        print("✅ Merkle root verified — Cloud data consistent with IoT reference.")
        return True

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

            if not self.verify_root_consistency():
                print("❌ Verification aborted — root mismatch.")
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
