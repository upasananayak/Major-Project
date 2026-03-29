import base64
import hashlib
import json
import os
import sys
import time
from collections import OrderedDict
from config import SERVER_KEM_SK
from pq_utils import decrypt_with_shared_key, kem_decapsulate, simple_hash, verify_signature
from typing import Dict, List, Tuple
from utils import pedersen_commit

from blockchain_dd import Blockchain


class SimpleVerifier:
    def __init__(self):
        
        # print(" Initializing Simple Verifier")
        self.root_hash = None
        self.timings = OrderedDict()

        
        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)


        assert hasattr(self, "ZK_PARAMS"), "ZK_PARAMS not loaded!"


    def load_data_from_iot(self, filename="iot_to_verifier_dec.json"):
        
        # print(f"\n Loading Data from IoT Device")
        
        try:
            with open(filename, 'r') as f:
                iot_data = json.load(f)

            self.input_file=iot_data["input_file"]
            # self.root_hash = iot_data["root_hash"]
            # self.root_signature = iot_data.get("root_signature")
            # self.public_key = iot_data.get("public_key")
            self.num_chunks = iot_data["num_chunks"]
            self.blocks_per_chunk = iot_data["blocks_per_chunk"]
            self.commitments = iot_data["commitments"]
           
            # print(f"   File info: {self.num_chunks} chunks, {self.blocks_per_chunk} blocks each")
            
            # root_bytes = self.root_hash.encode() if isinstance(self.root_hash, str) else str(self.root_hash).encode()
            # sig_ok = verify_signature(self.public_key, root_bytes, self.root_signature)
            
            # if not sig_ok:
            #     print("  PQ signature verification FAILED! Rejecting IoT data.")
            #     return False
            # print("  PQ signature verified successfully.")

            return True
            
        except FileNotFoundError:
            print(f"   Error: {filename} not found. Run IoT simulation first!")
            return False

    def decrypt_iot_verifier_file(self, enc_filename="iot_to_verifier.enc.json", out_filename="iot_to_verifier_dec.json"):
    
        # print("\n Decrypting IoT to Verifier encrypted payload (if present)")
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

            shared = kem_decapsulate(server_sk, ct)
            plaintext = decrypt_with_shared_key(shared, enc_payload)
            payload_json = json.loads(plaintext.decode())


            with open(out_filename, "w") as out_f:
                json.dump(payload_json, out_f, indent=2)

            # print(f"   Decrypted verifier payload written to: {out_filename}")
            return True
        except Exception as e:
            print(f"   Decryption failed: {e}")
            return False
        
    def load_proof_from_cloud(self, filename="cloud_to_verifier_dec.json"):
        
        # print(f"\n Loading Proof from Cloud Server")
        
        try:
            with open(filename, 'r') as f:
                self.proof_data = json.load(f)
            

            self.aai_data = self.proof_data["aai_data"]
            self.challenge_metadata = self.proof_data["challenge_metadata"]
            self.challenged_tags=self.proof_data["challenged_tags"]
            self.zk_proofs = self.proof_data.get("zk_proofs", [])
            self.cloud_root_hash = self.proof_data.get("cloud_root_hash")

            # print(f"   ZK proofs received: {len(self.zk_proofs)}")
            # print(f"   AAI data: {len(self.aai_data)}")
            # print(f"   Challenge metadata: {self.challenge_metadata}")
            # print("   Challenged tags received:", self.challenged_tags)
            return True
            
        except FileNotFoundError:
            print(f"   Error: {filename} not found. Run cloud server first!")
            return False

    def decrypt_cloud_proof_file(self, enc_filename="cloud_to_verifier.enc.json", out_filename="cloud_to_verifier_dec.json"):
        # print("\n Decrypting Cloud to Verifier encrypted proof (if present)")
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

            shared = kem_decapsulate(server_sk, ct)
            plaintext = decrypt_with_shared_key(shared, enc_payload)
            payload_json = json.loads(plaintext.decode())

            with open(out_filename, "w") as out_f:
                json.dump(payload_json, out_f, indent=2)

            # print(f"   Decrypted cloud proof written to: {out_filename}")
            return True
        except Exception as e:
            print(f"   Decryption failed: {e}")
            return False
        
    def verify_tag_imht(self):
        # print("    Verifying Tag-IMHT using real AAI paths...")
        
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
            
            current_hash = tag
            index = 1
            
            for node in aai_path:
                sibling_hash = node['hash_value']
                node_leaf_count = node['leaf_count'] *2 
                sigma = node['sigma']
                
                if sigma == 0:
                    combined = f"{node_leaf_count}||{sibling_hash}||{current_hash}"
                    index += node_leaf_count
                else:
                    combined = f"{node_leaf_count}||{current_hash}||{sibling_hash}"
                    
                current_hash = simple_hash(combined)
            
            
            # if current_hash != self.root_hash:
            #     print(f"    Verification failed for chunk {chunk}: computed root {current_hash} != expected root {self.root_hash}")
            #     return False
            # else:
            #     print(f"    AAI Verification succeeded for chunk {chunk}\n")
        
        # print("    All challenged chunks AAI verified successfully.")
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
                
            z_bytes = new_leaf_count
            
            current_bytes = current_hash
            sibling_bytes = sibling_hash
            
            if sigma == 0:
                data = z_bytes + sibling_bytes + current_bytes
            else:
                data = z_bytes + current_bytes + sibling_bytes
            
            current_hash = simple_hash(data)
            # print("         current bytes:", current_bytes)
            # print("         sibling bytes:", sibling_bytes)
            # print("         data hash:", current_hash)
            
            current_leaf_count = new_leaf_count
        
        return current_hash, computed_index

    def compute_commitment_hash_from_commitments(self):
        """
        Recompute commitment hash from individual Pedersen commitments
        """
        # print("\n Recomputing commitment hash from verifier-side commitments")

        commitment_concat = ""
        for idx, C in enumerate(self.commitments):
            commitment_concat += str(C) + "|"
            # print(f"   Commitment[{idx}] = {C}")

        self.recomputed_commitment_hash = simple_hash(commitment_concat)

        # print(f"   Recomputed Commitment Hash: {self.recomputed_commitment_hash}")
        return self.recomputed_commitment_hash
    
   

    def verify_zero_knowledge(self):
        # print("\n Verifying Pedersen challenge-dependent proof")

        proof = self.proof_data.get("zk_proofs", None)
        if not proof:
            print(" No proof data")
            return False

        z = self.challenge_metadata["z"]
        challenge_set = self.challenge_metadata["challenge_set"]
        p = self.ZK_PARAMS["p"]
        q = self.ZK_PARAMS["q"]

        # print("p:", p, "q", q, "z:", z)
        # print("proof:", proof, "\n")

        commitments = self.commitments

        C_agg_expected = 1
        for (chunk_id, a_i) in challenge_set:
            a_i = int(a_i) % q

            C_agg_expected = (C_agg_expected * pow(commitments[chunk_id], a_i, p)) % p
            
        m_sum = proof["m_sum"] % q
        r_sum = proof["r_sum"] % q

        ped_recomputed = pedersen_commit(m_sum, r_sum, self.ZK_PARAMS)

        expected_binding = hashlib.sha3_512(
            str(proof["C_agg"]).encode() + str(z).encode()
        ).hexdigest()

        # print("expected C_agg:", C_agg_expected)
        # print("pedersen recomputed from proof:", ped_recomputed, "\n")

        if ped_recomputed != C_agg_expected:
            # print(" Proof failed — recomputed Pedersen(commit(m_sum,r_sum)) != aggregated commitments")
            # print("expected:", C_agg_expected)
            # print("got (ped):", ped_recomputed)
            return False

        # print("Expected binding:", expected_binding)
        # print("Proof binding from cloud:", proof["proof_value"])

        # if expected_binding != proof["proof_value"]:
        #     print(" Proof binding mismatch (cloud did not include z correctly)")
            return False

        # print("\n ZK Pedersen-style proof verified successfully.")
        return True

    # def verify_root_consistency(self):
    #     print("\n Verifying Merkle Root Consistency (IoT vs Cloud)")

    #     iot_root = self.root_hash

    #     if not self.cloud_root_hash:
    #         print(" Cloud proof missing Merkle root!")
    #         return False

    #     print(f"   IoT root:   {iot_root}")
    #     print(f"   Cloud root: {self.cloud_root_hash}")

    #     if iot_root != self.cloud_root_hash:
    #         print(" Merkle root mismatch! Cloud data has been modified.")
    #         return False

    #     print(" Merkle root verified — Cloud data consistent with IoT reference.")
    #     return True

    # def run_complete_verification(self):

    #  #bc = BlockchainClient()   # 🔗 blockchain client
    #  bc = Blockchain()
     

    #  try:
    #     self.decrypt_iot_verifier_file()
    #     if not self.load_data_from_iot():
    #        # bc.submit_verification(self.input_file, "INVALID")
    #         return False

    #     self.root_hash=bc.get_latest_root_hash_int(self.input_file)
    #     self.decrypt_cloud_proof_file()
    #     if not self.load_proof_from_cloud():
    #        # bc.submit_verification(self.input_file, "INVALID")
    #         return False

    #     if not self.verify_tag_imht():
    #         print("\n Tag-IMHT verification failed!")
    #         return False

    #     # if not self.verify_root_consistency():
    #     #     print(" Verification aborted — root mismatch.")
          
    #     #     return False

    #     if not self.verify_zero_knowledge():
    #         print("\n ZK proof verification failed!")
    #         return False

    #     self.recomputed_commitment_hash = self.compute_commitment_hash_from_commitments()
       
        
    #     # ALL CHECKS PASSED
    #     latest_version = bc.get_latest_version(self.input_file)
    #     bc.submit_verification(self.input_file,latest_version, self.cloud_root_hash,self.recomputed_commitment_hash)
    #     verified= bc.get_latest_status(self.input_file)

    #     if verified:

    #         print("\n VERIFICATION SUCCESSFUL!")
    #         print(f"   • Tag-IMHT integrity:  VERIFIED")
    #         print(f"   • Cloud data integrity:  CONFIRMED")
    #         print(f"   • System security:  MAINTAINED")

    #         return True

    #  except Exception as e:
    #     print(f"\n Error in verification: {e}")
    #   #  bc.submit_verification(self.input_file, "INVALID")
    #     return False

    def _print_timing_report(self):
        # print("\n" + "=" * 60)
        # print(" VERIFIER TIMING REPORT")
        # print("=" * 60)

        for stage, t in self.timings.items():
            print(f" {stage:<35} : {t*1000:.3f} ms")

        print("=" * 60)

    def run_complete_verification(self):

        bc = Blockchain()
        total_start = time.perf_counter()

        try:
            # ---------------- IoT Decryption ----------------
            t0 = time.perf_counter()
            self.decrypt_iot_verifier_file()
            self.timings["IoT Payload Decryption"] = time.perf_counter() - t0

            # ---------------- IoT Load ----------------
            t0 = time.perf_counter()
            if not self.load_data_from_iot():
                return False
            self.timings["IoT Data Loading"] = time.perf_counter() - t0

            # ---------------- Blockchain Fetch ----------------
            t0 = time.perf_counter()
            self.root_hash = bc.get_latest_root_hash_int(self.input_file)
            self.timings["Blockchain Root Fetch"] = time.perf_counter() - t0

            # ---------------- Cloud Decryption ----------------
            t0 = time.perf_counter()
            self.decrypt_cloud_proof_file()
            self.timings["Cloud Proof Decryption"] = time.perf_counter() - t0

            # ---------------- Cloud Load ----------------
            t0 = time.perf_counter()
            if not self.load_proof_from_cloud():
                return False
            self.timings["Cloud Proof Loading"] = time.perf_counter() - t0

            # ---------------- Tag-IMHT ----------------
            t0 = time.perf_counter()
            if not self.verify_tag_imht():
                return False
            self.timings["Tag-IMHT Verification"] = time.perf_counter() - t0

            # ---------------- ZK Proof ----------------
            t0 = time.perf_counter()
            if not self.verify_zero_knowledge():
                return False
            self.timings["ZK Proof Verification"] = time.perf_counter() - t0

            # ---------------- Commitment Hash ----------------
            t0 = time.perf_counter()
            self.recomputed_commitment_hash = self.compute_commitment_hash_from_commitments()
            self.timings["Commitment Hash Recompute"] = time.perf_counter() - t0

            # ---------------- Blockchain Submit ----------------
            t0 = time.perf_counter()
            latest_version = bc.get_latest_version(self.input_file)
            bc.submit_verification(
                self.input_file,
                latest_version,
                self.cloud_root_hash,
                self.recomputed_commitment_hash
            )
            verified = bc.get_latest_status(self.input_file)
            self.timings["Blockchain Verification Submit"] = time.perf_counter() - t0

            self.timings["Total Verification Time"] = time.perf_counter() - total_start

            # ---------------- RESULT ----------------
            if verified:
                # print("\n VERIFICATION SUCCESSFUL!")
                # self._print_timing_report()
                return True

        except Exception as e:
            print(f"\n Error in verification: {e}")
            return False



def main():

    # print("Starting Simple Verifier Simulation...")

    verifier = SimpleVerifier()
    success = verifier.run_complete_verification()
    
    if success:
        # print("The cloud data is intact and secure! ")
        sys.exit(0)
    else:
        # print("\n Verification failed! Data integrity compromised!")
        sys.exit(1)

if __name__ == "__main__":
    main()
