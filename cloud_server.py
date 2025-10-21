#!/usr/bin/env python3
"""
Simple Cloud Server - IIoT Storage Verification System
Based on the IEEE paper's ProofGen algorithm
"""

import json
import random
from utils import HHF, eval_polynomial, P, PSI, pseudo_random_permutation, pseudo_random_function
from pq_utils import generate_zk_proof, simple_hash
import numpy.polynomial.polynomial as PolyDiv
import numpy as np

class SimpleCloudServer:
    def __init__(self):
        """Initialize cloud server"""
        print(" Initializing Simple Cloud Server")
        self.stored_data = None
        self.received_data = False

    def load_data_from_iot(self, filename="iot_to_cloud.json"):
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
            proof = generate_zk_proof(
                commitment=commit_data["commitment"],
                poly_value=eval_polynomial(commit_data["coeffs"], PSI, P),
                r=commit_data["r"]
            )
            self.zk_proofs.append(proof)
            print(f"   Chunk {chunk_id}: ZK proof generated.")

        
        print(f"\n STEP 3: Generating Storage Proof (ProofGen)")
        
        if not hasattr(self, 'challenge_set'):
            print("   Error: No challenge received!")
            return None
        
        random.seed(12345)  # fixed seed ensures same beta each run
        beta = random.randint(1, 96)
        print(f" Selected beta: {beta}")
        
        # Compute B = HHF(beta)
        B = HHF(beta)
        print(f"Computed B = HHF(beta): {B}")
        
        # Compute eta = simple_hash(B)
        eta = simple_hash(B)
        print(f"Computed eta = simple_hash(B): {eta}")
        
        # Save as attributes if needed
        self.beta = beta
        self.B = B
        self.eta = eta


        # Construct proof polynomial (Paper equation 1)
        # P_prf(x) = Σ(a_i * F_i,0) + Σ(a_i * F_i,1) * x + Σ(a_i * F_i,2) * x² + ...
        proof_poly_coeffs = [0] * self.metadata["blocks_per_chunk"]
        
        print(f"   Constructing proof polynomial from challenged chunks:")
        for chunk_id, coefficient in self.challenge_set:
            chunk_data = self.file_chunks[chunk_id]
            print(f"     Chunk {chunk_id} × {coefficient}: {chunk_data}")
            
            # Add coefficient × chunk to proof polynomial
            for i, block in enumerate(chunk_data):
                proof_poly_coeffs[i] = (proof_poly_coeffs[i] + coefficient * block) % P
                print(f"block: {block}, coeff: {coefficient}, updated coeffs[{i}]: {proof_poly_coeffs[i]}")
        
        print(f"   Proof polynomial P_prf(x) before beta*eta: {proof_poly_coeffs}")
        proof_poly_coeffs[0]= self.beta * self.eta % P
        print(f"   Proof polynomial P_prf(x): {proof_poly_coeffs}")
        
        self.proof_poly_at_z = eval_polynomial(proof_poly_coeffs, self.z, P)

        # Evaluate P_prf(z) (Paper algorithm)
        numerator = proof_poly_coeffs
        numerator[0] = numerator[0] - self.proof_poly_at_z
        denominator = [-self.z, 1]  # (x - z)
        quotient, remainder  =  PolyDiv.polydiv(numerator, denominator)

        quotient = np.round(quotient).astype(int)
        remainder = np.round(remainder).astype(int)
        print("numerator:", numerator, "denominator:", denominator)
        #print(f"   P_prf({self.z}) = {self.proof_poly_at_z}")
        
        # Calculate polynomial quotient Z_prf(x) = (P_prf(x) - P_prf(z))/(x - z)
        # This is simplified for our small numbers
        self.quotient_poly = quotient.tolist()
        print(f"   Quotient polynomial Z_prf(x): {self.quotient_poly}")
        
        # Select fixed beta < 97 (same each time) - you can fix seed or hardcode value
        
        self.export_proof_for_verifier(out_filename="cloud_to_verifier_test.json")

        # Generate auxiliary authentication information (AAI) for each challenged tag
        # self.aai_data = {}
        # for chunk_id, _ in self.challenge_set:
        #     # In real implementation, this would be Merkle tree path
        #     # For simplicity, we store the tag and a simple "proof"
        #     generate_aai = self.generate_aai(chunk_id)
        #     print(f"   AAI for chunk {chunk_id}: {generate_aai}")
        #     self.aai_data[chunk_id] = {
        #         "tag": self.homomorphic_tags[chunk_id],
        #         "path_proof": f"merkle_path_{chunk_id}"  # Simplified
        #     }
        # print(f"   Generated AAI for {len(self.aai_data)} challenged chunks")


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
            "quotient_polynomial": self.quotient_poly,
            "aai_data": self.aai_data,
            "proof_poly_at_z": self.proof_poly_at_z,
            "challenge_metadata": {
                "challenge_set": self.challenge_set,
                "z": self.z,
                "k1": self.k1,
                "k2": self.k2,
                "c": self.c
            },
            "challenged_tags": self.challenged_tags,
            "homomorphic_tags": self.homomorphic_tags,
            "B": self.B,
            "zk_proofs": self.zk_proofs
        }

        # Prepare complete proof (Paper's prf format)
        return self.proof
    
    def export_proof_for_verifier(self, out_filename="cloud_to_verifier.json"):
        challenged_indices = [cid for (cid, _) in self.challenge_set]

        # Build commitments list aligned with challenged_indices
        commitments = []
        for cid in challenged_indices:
            entry = self.polynomial_commitments[cid]
            # adapt depending on how you store commitments:
            # if stored as dict: {"commitment": <int>} else plain int
            if isinstance(entry, dict):
                C = int(entry.get("commitment", entry.get("C", 0)))
            else:
                C = int(entry)
            commitments.append(C)

        proof_obj = {
            "challenge_set": self.challenge_set,
            "z": int(self.z),
            "P_prf_z": int(self.proof_poly_at_z),
            "quotient_poly": [int(x) for x in self.quotient_poly],
            "challenged_indices": challenged_indices,
            "commitments": commitments,
            "note": "FULL_OPENING_MODE: numeric commitments (P_Fi(psi)) provided to verifier"
        }

        with open(out_filename, "w") as f:
            json.dump(proof_obj, f, indent=2)

        print(f"Proof exported to {out_filename}")
        return proof_obj

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

    def _compute_quotient_polynomial(self, proof_poly_coeffs, z, proof_at_z):
        """Compute quotient polynomial for KZG-style proof"""
        # For our simplified implementation, return a simple quotient
        # In real implementation, this would be proper polynomial division
        quotient_coeffs = []
        for i in range(len(proof_poly_coeffs) - 1):
            # Simplified quotient calculation
            coeff = (proof_poly_coeffs[i + 1] + i) % P
            quotient_coeffs.append(coeff)
        
        return quotient_coeffs if quotient_coeffs else [1]

    def send_proof_to_verifier(self, filename="cloud_to_verifier.json"):
        """Step 4: Send proof to verifier"""
        print(f"\n STEP 4: Sending Proof to Verifier")
        
        if not hasattr(self, 'proof'):
            print("   Error: No proof generated!")
            return False
        
        # Save proof to file
        with open(filename, 'w') as f:
            json.dump(self.proof, f, indent=2)
        
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