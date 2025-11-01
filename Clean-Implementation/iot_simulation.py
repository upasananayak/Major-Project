"""
Simple IIoT Storage Verification System
Based on the IEEE paper: "Efficient and Secure Storage Verification in Cloud-Assisted Industrial IoT Networks"
"""

import os
import json
from config import SERVER_KEM_PUB
from utils import HHF
from pq_utils import generate_sig_keypair, sign_message, kem_encapsulate, encrypt_with_shared_key, simple_hash
import base64
import random
from utils import pedersen_commit

BLOCKS_PER_CHUNK = 4    # n = 4 blocks per chunk 
BLOCK_SIZE_BITS = 8     # Each block is 8-bit integer

class SimpleIIoTDevice:
    def __init__(self):
        print(" Initializing Simple IIoT Device")

        self.pk, self.sk = generate_sig_keypair()
        print(f"Generated PQ signature keypair for IIoT device")

        print(f"   Blocks per chunk: {BLOCKS_PER_CHUNK}")
        print(f"   Block size: {BLOCK_SIZE_BITS}-bit integers")

        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)
        print("ZK PARAMS loaded")

        assert hasattr(self, "ZK_PARAMS"), "ZK_PARAMS not loaded!"


    def process_file(self, filename):
        print(f"\n File Processing - {filename}")
        
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                f.write("Hello IIoT! Test data for storage verification.")
            print(f"   Created sample file: {filename}")
        
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        print(f"   File size: {len(file_data)} bytes")

        self.chunks = self._file_to_chunks(file_data)

        print(f"   Created {len(self.chunks)} chunks")
        

        for i, chunk in enumerate(self.chunks):
            print(f"   Chunk {i}: {chunk}")
        
        return self.chunks

    def _file_to_chunks(self, file_data):
        chunks = []
        
        for i in range(0, len(file_data), BLOCKS_PER_CHUNK):
            chunk_bytes = file_data[i:i+BLOCKS_PER_CHUNK]
            
            chunk_blocks = []
            for byte_val in chunk_bytes:
                small_int = (byte_val % 21)  
                chunk_blocks.append(small_int)
            
            while len(chunk_blocks) < BLOCKS_PER_CHUNK:
                chunk_blocks.append(0)
            
            chunks.append(chunk_blocks)
        
        return chunks

    def generate_homomorphic_tags(self):
        print(f"\n Homomorphic Tag Generation (Pedersen commitments)")

        self.homomorphic_tags = []
        self.polynomial_commitments = []

        p = self.ZK_PARAMS["p"]
        q = self.ZK_PARAMS["q"]

        for i, chunk in enumerate(self.chunks):
            chunk_bytes = bytes(chunk)

            m_i = int.from_bytes(chunk_bytes, "big") % q

            r = random.SystemRandom().randint(1, q-1)

            commitment = pedersen_commit(m_i, r, self.ZK_PARAMS)

            tag = HHF(commitment)

            self.polynomial_commitments.append({
                "coeffs": chunk,                 
                "r": r,
                "commitment": commitment,
                "m_i": m_i                     
            })

            self.homomorphic_tags.append(tag)
            print(f"   Chunk {i}: m_i={m_i}, r_i={r}, commitment={commitment}, tag={tag}")

        print(f"   Generated {len(self.homomorphic_tags)} homomorphic (Pedersen) tags")

        return self.homomorphic_tags

    def build_tag_imht(self):
        print(f"\n Tag-IMHT Construction")
        
        tag_hashes = []
        for i, tag in enumerate(self.homomorphic_tags):
            tag_hash = simple_hash(tag)
            tag_hashes.append(tag_hash)
            print(f"   h(ϖ{i}) = {tag_hash}")
        
        self.root_hash = self._build_merkle_tree(tag_hashes)
        print(f"   Tag-IMHT Root Hash: {self.root_hash}")
        
        return self.root_hash

    def _build_merkle_tree(self, leaf_hashes):
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

                parent = simple_hash(f"{z}||{left}||{right}")
                print(f"   h({z}||{left}||{right}) = {parent}")
                next_level.append(parent)
            current_level = next_level
        
        return current_level[0]

    def upload_data(self):
        print(f"\n  Data Upload")
        
        cloud_data = {
            "input_file":self.input_filename,
            "random_values": [pc["r"] for pc in self.polynomial_commitments],
            "homomorphic_tags": self.homomorphic_tags,
            "metadata": {
                "num_chunks": len(self.chunks),
                "blocks_per_chunk": BLOCKS_PER_CHUNK,
            }
        }

        root_bytes = self.root_hash.encode() if isinstance(self.root_hash, str) else str(self.root_hash).encode()
        signature = sign_message(self.sk, root_bytes)

        
        verifier_data = {
            "input_file":self.input_filename,
            "root_hash": self.root_hash,
            "root_signature": signature.hex(),
            "public_key": self.pk.hex(),
            "num_chunks": len(self.chunks),
            "blocks_per_chunk": BLOCKS_PER_CHUNK,
            "commitments": [pc["commitment"] for pc in self.polynomial_commitments]
        }
        

        cloud_json = json.dumps(cloud_data).encode()
        verifier_json = json.dumps(verifier_data).encode()

        if not os.path.exists(SERVER_KEM_PUB):
            raise FileNotFoundError(f"Server public key not found: {SERVER_KEM_PUB}")
        with open(SERVER_KEM_PUB, "r") as f:
            server_pk = base64.b64decode(f.read().strip())

        ct, shared = kem_encapsulate(server_pk)

        cloud_encrypted_payload = encrypt_with_shared_key(shared, cloud_json)

        verifier_encrypted_payload = encrypt_with_shared_key(shared, verifier_json)

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
        
        print(f"   Data sent to cloud")
        print(f"   Root hash sent to verifier")
        print(f"   Files created: iot_to_cloud.json, iot_to_verifier.json")
        
        return cloud_data, verifier_data

    def run_complete_workflow(self, filename="input.txt"):
        self.input_filename = filename
        try:
            self.process_file(filename)
            self.generate_homomorphic_tags()  
            self.build_tag_imht()
            self.upload_data()
            
            print("\n IIoT Device Workflow Completed Successfully!")
            print(f"   • File processed: {len(self.chunks)} chunks")
            print(f"   • Tags generated: {len(self.homomorphic_tags)} lightweight homomorphic tags")
            print(f"   • Tag-IMHT root: {self.root_hash}")
            print(f"   • Ready for cloud server and verifier!")
            
            return True
            
        except Exception as e:
            print(f"\n Error in workflow: {e}")
            return False

def main():
    filename = input("Enter filename (press Enter for 'input.txt'): ").strip()
    if not filename:
        filename = "input.txt"
    print(f"Using file: {filename}")
    
    device = SimpleIIoTDevice()
    success = device.run_complete_workflow(filename)
    
    if success:
        print("\n IoT Simulation completed successfully!")
        
    else:
        print("\n Simulation failed!")

if __name__ == "__main__":
    main()