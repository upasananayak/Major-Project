"""
Simple IIoT Storage Verification System
Based on the IEEE paper: "Efficient and Secure Storage Verification in Cloud-Assisted Industrial IoT Networks"
"""
from pq_utils import set_demo_deterministic_seed
set_demo_deterministic_seed()

import hashlib
import os
import json
from config import SERVER_KEM_PUB
from utils import HHF, eval_polynomial, P, PSI
from pq_utils import generate_sig_keypair, sign_message, kem_keypair, kem_encapsulate, encrypt_with_shared_key, decrypt_with_shared_key, simple_hash
from kzg import MiniKZG
import oqs
import base64
import random

BLOCKS_PER_CHUNK = 4    # n = 4 blocks per chunk 
BLOCK_SIZE_BITS = 8     # Each block is 8-bit integer

class SimpleIIoTDevice:
    def __init__(self):
        """Initialize lightweight IIoT device"""
        print(" Initializing Simple IIoT Device")
        self.secret_psi = PSI  # Use the small secret from utils
        self.kzg = MiniKZG(max_degree=BLOCKS_PER_CHUNK)
        self.pk, self.sk = generate_sig_keypair()
        print(f"Generated PQ signature keypair for device:\n  Public Key: {self.pk}\n   Secret Key: {self.sk}")
        print(f"   Secret ψ: {self.secret_psi}")
        print(f"   Blocks per chunk: {BLOCKS_PER_CHUNK}")
        print(f"   Block size: {BLOCK_SIZE_BITS}-bit integers")
        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)
        print("ZK PARAMS fingerprint:", (self.ZK_PARAMS["p"] % 2**32, self.ZK_PARAMS["q"] % 2**32))

    def setup_system(self):
        """Step 1: Setup - Generate public parameters (Paper Section IV.E)"""
        print("\n STEP 1: System Setup")
        # Public parameters are already in KZG setup
        print(f"   Public parameters: {self.kzg.public_params}")
        print(f"   System ready for file processing")
        return True

    def process_file(self, filename):
        """Step 2: File Processing (Paper Store Algorithm)"""
        print(f"\n STEP 2: File Processing - {filename}")
        
        # Read file
        if not os.path.exists(filename):
            # Create sample file if not exists
            with open(filename, 'w') as f:
                f.write("Hello IIoT! Test data for storage verification.")
            print(f"   Created sample file: {filename}")
        
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        print(f"   File size: {len(file_data)} bytes")
        
        # Convert file to chunks
        self.chunks = self._file_to_chunks(file_data)
        print(f"   Created {len(self.chunks)} chunks")
        
        # Display chunks
        for i, chunk in enumerate(self.chunks):
            print(f"   Chunk {i}: {chunk}")
        
        return self.chunks

    def _file_to_chunks(self, file_data):
        """Convert file bytes to small integer chunks"""
        chunks = []
        
        # Process file in groups of BLOCKS_PER_CHUNK bytes
        for i in range(0, len(file_data), BLOCKS_PER_CHUNK):
            chunk_bytes = file_data[i:i+BLOCKS_PER_CHUNK]
            
            # Convert each byte to small integer (0-20 range)
            chunk_blocks = []
            for byte_val in chunk_bytes:
                small_int = (byte_val % 21)  # Keep in 0-20 range for small numbers
                chunk_blocks.append(small_int)
            
            # Pad if necessary
            while len(chunk_blocks) < BLOCKS_PER_CHUNK:
                chunk_blocks.append(0)
            
            chunks.append(chunk_blocks)
        
        return chunks


    def hash_commitment(self,poly_value, r):
        """Hash-based polynomial commitment (post-quantum safe)"""
        data = f"{poly_value}|{r}".encode()
        digest = int(hashlib.sha3_256(data).hexdigest(), 16) % P
        return digest
    
    def pedersen_commit(self, m, r, params):
        p, g, h = params["p"], params["g"], params["h"]
        return (pow(g, m, p) * pow(h, r, p)) % p


    def generate_homomorphic_tags(self):
        """Step 3: Generate homomorphic tags (Full-opening debug version)"""
        print(f"\n STEP 3: Homomorphic Tag Generation (Full-Opening Debug Mode)")

        self.homomorphic_tags = []
        self.polynomial_commitments = []

        for i, chunk in enumerate(self.chunks):
            polynomial_coeffs = chunk  # coefficients = chunk blocks

            # Randomness r per chunk (for simulation)
            r = random.randint(1, P - 1)

            poly_value = eval_polynomial(polynomial_coeffs, self.secret_psi, self.ZK_PARAMS["q"]) % self.ZK_PARAMS["q"]
            commitment = self.pedersen_commit(poly_value, r, self.ZK_PARAMS)

            # Homomorphic tag as hash of commitment
            tag = HHF(commitment)

            # Store everything for full-opening verification
            self.polynomial_commitments.append({
                "coeffs": polynomial_coeffs,
                "r": r,
                "commitment": commitment
            })

            self.homomorphic_tags.append(tag)
            print(f"   Chunk {i}: coeffs={polynomial_coeffs}, r={r}, P(ψ)={poly_value}, commitment={commitment}, tag={tag}")

        print(f"   Generated {len(self.homomorphic_tags)} homomorphic tags (Full Opening Stored)")
        return self.homomorphic_tags

    def build_tag_imht(self):
        """Step 4: Build Tag-IMHT (Paper Section IV.D)"""
        print(f"\n STEP 4: Tag-IMHT Construction")
        
        # Hash each tag for tree construction
        tag_hashes = []
        for i, tag in enumerate(self.homomorphic_tags):
            tag_hash = simple_hash(tag)
            tag_hashes.append(tag_hash)
            print(f"   h(ϖ{i}) = {tag_hash}")
        
        # Build simple binary tree
        self.root_hash = self._build_merkle_tree(tag_hashes)
        print(f"   Tag-IMHT Root Hash: {self.root_hash}")
        
        return self.root_hash

    def _build_merkle_tree(self, leaf_hashes):
        """Simple Merkle tree construction"""
        if len(leaf_hashes) == 1:
            return leaf_hashes[0]
        
        z = 1

        current_level = leaf_hashes[:]
        while len(current_level) > 1:
            next_level = []
            z*=2
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                # Paper formula: h(z||hlc||hrc)
                
                parent = simple_hash(f"{z}||{left}||{right}")
                print(f"   h({z}||{left}||{right}) = {parent}")
                next_level.append(parent)
            current_level = next_level
        
        return current_level[0]

    def upload_data(self):
        """Step 5: Upload to cloud and verifier (Paper workflow)"""
        print(f"\n  STEP 5: Data Upload")
        
        # Prepare data for cloud server
        cloud_data = {
            "file_chunks": self.chunks,
            "homomorphic_tags": self.homomorphic_tags,
            "polynomial_commitments": self.polynomial_commitments,
            "metadata": {
                "num_chunks": len(self.chunks),
                "blocks_per_chunk": BLOCKS_PER_CHUNK,
                "secret_psi": self.secret_psi  # Normally secret, but for simulation
            }
        }

        root_bytes = self.root_hash.encode() if isinstance(self.root_hash, str) else str(self.root_hash).encode()
        signature = sign_message(self.sk, root_bytes)

        # Prepare data for verifier
        verifier_data = {
            "root_hash": self.root_hash,
            "root_signature": signature.hex(),
            "public_key": self.pk.hex(),
            "public_parameters": self.kzg.public_params,
            "num_chunks": len(self.chunks),
            "blocks_per_chunk": BLOCKS_PER_CHUNK,
            "polynomial_commitments": self.polynomial_commitments  # provide commitments for verifier checks

        }
        

        cloud_json = json.dumps(cloud_data).encode()
        verifier_json = json.dumps(verifier_data).encode()

        if not os.path.exists(SERVER_KEM_PUB):
            raise FileNotFoundError(f"Server public key not found: {SERVER_KEM_PUB}. Run `python3 config.py` to generate keys or copy server key.")
        with open(SERVER_KEM_PUB, "r") as f:
            server_pk = base64.b64decode(f.read().strip())

        # Encapsulate to server public key and encrypt payload
        ct, shared = kem_encapsulate(server_pk)
        cloud_encrypted_payload = encrypt_with_shared_key(shared, cloud_json)
        verifier_encrypted_payload = encrypt_with_shared_key(shared, verifier_json)

        # Save ct and encrypted payload as base64 JSON fields (deterministic parsing)
        cloud_out_obj = {
            "ct": base64.b64encode(ct).decode(),
            "enc_payload": base64.b64encode(cloud_encrypted_payload).decode()
        }

        verifier_out_obj = {
            "ct": base64.b64encode(ct).decode(),
            "enc_payload": base64.b64encode(verifier_encrypted_payload).decode()
        }
        
        with open("iot_to_cloud.enc.json", "w") as f:
            json.dump(cloud_out_obj, f, indent=2)
            
        with open('iot_to_verifier.enc.json', 'w') as f:
            json.dump(verifier_out_obj, f, indent=2)
        
        print(f"   Data sent to cloud: {len(self.chunks)} chunks + {len(self.homomorphic_tags)} tags")
        print(f"   Root hash sent to verifier: {self.root_hash}")
        print(f"   Files created: iot_to_cloud.json, iot_to_verifier.json")
        
        return cloud_data, verifier_data

    def run_complete_workflow(self, filename="input.txt"):
        """Execute complete IIoT device workflow from the paper"""
        print("=" * 60)
        print(" IIoT Storage Verification System - Device Simulation")
        print(" Based on IEEE Paper: 'Efficient and Secure Storage Verification'")
        print("=" * 60)
        
        try:
            # Execute all steps according to paper
            self.setup_system()
            self.process_file(filename)
            self.generate_homomorphic_tags()  # Paper's main contribution
            self.build_tag_imht()
            self.upload_data()
            
            print("\n IIoT Device Workflow Completed Successfully!")
            print("=" * 60)
            print(f" Summary:")
            print(f"   • File processed: {len(self.chunks)} chunks")
            print(f"   • Tags generated: {len(self.homomorphic_tags)} lightweight homomorphic tags")
            print(f"   • Tag-IMHT root: {self.root_hash}")
            print(f"   • Ready for cloud server and verifier!")
            
            return True
            
        except Exception as e:
            print(f"\n Error in workflow: {e}")
            return False

def main():
    """Main function"""
    print("Starting Simple IIoT Device Simulation...")
    
    # Get filename
    filename = input("Enter filename (press Enter for 'input.txt'): ").strip()
    if not filename:
        filename = "input.txt"
    print(f"Using file: {filename}")
    
    # Run IIoT device
    device = SimpleIIoTDevice()
    success = device.run_complete_workflow(filename)
    
    if success:
        print("\n Ready for next steps:")
        print("   1. Run cloud server simulation")
        print("   2. Run verifier simulation")
    else:
        print("\n Simulation failed!")

if __name__ == "__main__":
    main()