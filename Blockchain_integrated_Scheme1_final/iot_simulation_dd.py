"""
Simple IIoT Storage Verification System
Based on the IEEE paper: "Efficient and Secure Storage Verification in Cloud-Assisted Industrial IoT Networks"
"""

import os
import json
import base64
import random
import hashlib
from config import SERVER_KEM_PUB
from utils import HHF, pedersen_commit
from pq_utils import (
    generate_sig_keypair,
    sign_message,
    kem_encapsulate,
    encrypt_with_shared_key,
    simple_hash
)
from blockchain_dd import Blockchain

BLOCKS_PER_CHUNK = 4 #n=4,30,
BLOCK_SIZE_BITS = 8


class SimpleIIoTDevice:
    def __init__(self):
        # print(" Initializing Simple IIoT Device")

        self.pk, self.sk = generate_sig_keypair()
        self.blockchain = Blockchain()

        # print(f"Generated PQ signature keypair for IIoT device")

        # print(f"   Blocks per chunk: {BLOCKS_PER_CHUNK}")
        # print(f"   Block size: {BLOCK_SIZE_BITS}-bit integers")

        with open("zk_params.json", "r") as f:
            self.ZK_PARAMS = json.load(f)
            # print("ZK PARAMS loaded")

        assert hasattr(self, "ZK_PARAMS"), "ZK_PARAMS not loaded!"

        # ---- ADDED STATE (for data dynamics) ----
        self.leaf_hashes = []     # Merkle leaves
        self.commitments = []     # Pedersen commitments
        # ----------------------------------------

    # ------------------ ORIGINAL CODE ------------------

    def process_file(self, filename):
        # print(f"\n File Processing - {filename}")
        
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                f.write("Hello IIoT! Test data for storage verification.")
            # print(f"   Created sample file: {filename}")
        
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        # print(f"   File size: {len(file_data)} bytes")

        self.chunks = self._file_to_chunks(file_data)

        # print(f"   Created {len(self.chunks)} chunks")
        

        # for i, chunk in enumerate(self.chunks):
        #     print(f"   Chunk {i}: {chunk}")
        
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
    
    # def generate_homomorphic_tags(self):
    #     print(f"\n Homomorphic Tag Generation (Pedersen commitments)")

    #     self.homomorphic_tags = []
    #     self.polynomial_commitments = []

      
    #     q = self.ZK_PARAMS["q"]

    #     for i, chunk in enumerate(self.chunks):
    #         chunk_bytes = bytes(chunk)

    #         m_i = int.from_bytes(chunk_bytes, "big") % q

    #         r = random.SystemRandom().randint(1, q-1)

    #         commitment = pedersen_commit(m_i, r, self.ZK_PARAMS)

    #         tag = HHF(commitment)

    #         self.polynomial_commitments.append({
    #             "coeffs": chunk,                 
    #             "r": r,
    #             "commitment": commitment,
    #             "m_i": m_i                     
    #         })

    #         self.homomorphic_tags.append(tag)
    #         print(f"   Chunk {i}: m_i={m_i}, r_i={r}, commitment={commitment}, tag={tag}")

    #     print(f"   Generated {len(self.homomorphic_tags)} homomorphic (Pedersen) tags")

    #     return self.homomorphic_tags

    def generate_homomorphic_tags(self, chunks):
        # print(f"   • Processing {len(chunks)} chunks (Checking Cache...)")
        
        cache = self.load_cache()
        new_cache = {}
        
        # We now maintain TWO lists
        commitments = []     # Raw Integers (For Blockchain Math)
        tags = []            # Hashed Values (For Merkle Tree)
        
        random_values = []
        self.polynomial_commitments = [] 
        
        reused_count = 0
        q = self.ZK_PARAMS['q']

        for i, chunk_list in enumerate(chunks):
            # 1. Convert List to Integer
            chunk_bytes = bytes(chunk_list) 
            m_scalar = int.from_bytes(chunk_bytes, "big") % q

            # 2. Cache Key
            chunk_str = str(chunk_list)
            chunk_hash = hashlib.sha256(chunk_str.encode()).hexdigest()
            
            if chunk_hash in cache:
                # HIT
                r = cache[chunk_hash]['r']
                comm = cache[chunk_hash]['commitment']
                reused_count += 1
            else:
                # MISS
                r = random.SystemRandom().randrange(1, q)
                comm = pedersen_commit(m_scalar, r, self.ZK_PARAMS)
            
            # --- THE FIX: SPLIT RAW vs HASHED ---
            # 1. Save Raw Commitment (Big Integer) for the Blockchain Registry
            commitments.append(comm)
            
            # 2. Save Hashed Tag (HHF) for the Merkle Tree
            # This matches what Cloud Server expects!
            tag = HHF(comm) 
            tags.append(tag)
            # ------------------------------------

            random_values.append(r)
            
            # Store Raw commitment in polynomial list (Verification needs the raw values to check proof)
            self.polynomial_commitments.append({
                  "coeffs": chunk_list,                  
                  "r": r,
                  "commitment": comm, # Keep Raw here
                  "m_i": m_scalar                      
            })
            
            new_cache[chunk_hash] = {'r': r, 'commitment': comm}

        self.save_cache(new_cache)
        
        # print(f"   [EFFICIENCY REPORT]")
        # print(f"   Reused from Cache : {reused_count}")
        # print(f"   Newly Computed    : {len(chunks) - reused_count}")

        # Save to class instance correctly
        self.commitments = commitments       # RAW -> For Blockchain
        self.homomorphic_tags = tags         # HASHED -> For Merkle Tree
        
        return commitments, random_values
    
    def build_tag_imht(self):
        # print(f"\n Tag-IMHT Construction")
        
        tag_hashes = []
        for i, tag in enumerate(self.homomorphic_tags):
            tag_hash = simple_hash(tag)
            tag_hashes.append(tag_hash)
            # print(f"   h(omega{i}) = {tag_hash}")
        
        self.root_hash = self._build_merkle_tree(tag_hashes)
        # print(f"   Tag-IMHT Root Hash: {self.root_hash}")
        
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
                # print(f"   h({z}||{left}||{right}) = {parent}")
                next_level.append(parent)
            current_level = next_level
        
        return current_level[0]
    
    def upload_data(self):
        # print(f"\n  Data Upload")
        
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

        #print(len(self.chunks))
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
        
        # print(f"   Data sent to cloud")
        # print(f"   Root hash sent to verifier")
        # print(f"   Files created: iot_to_cloud.json, iot_to_verifier.json")
        
        return cloud_data, verifier_data
    
    
    def compute_commitment_hash(self):
        """
        Compute a single hash over all Pedersen commitments
        """
        commitment_concat = ""

        for pc in self.polynomial_commitments:
            commitment_concat += str(pc["commitment"]) + "|"

        self.commitment_hash = simple_hash(commitment_concat)

        # print(f"\n Commitment Hash (all chunks): {self.commitment_hash}")
        return self.commitment_hash

    def load_cache(self):
        if os.path.exists("iot_cache.json"):
            try:
                with open("iot_cache.json", "r") as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def save_cache(self, cache_data):
        with open("iot_cache.json", "w") as f:
            json.dump(cache_data, f)

   
   
    def run_complete_workflow(self, filename="input.txt"):
        self.input_filename = filename
        try:
            self.process_file(filename)
            self.generate_homomorphic_tags(self.chunks)  
            self.build_tag_imht()
            self.compute_commitment_hash()
            self.upload_data()
            
            # print("\n IIoT Device Workflow Completed Successfully!")
            # print(f"   • File processed: {len(self.chunks)} chunks")
            # print(f"   • Tags generated: {len(self.homomorphic_tags)} lightweight homomorphic tags")
            # print(f"   • Tag-IMHT root: {self.root_hash}")
            # print(f"   • Ready for cloud server and verifier!")

            # print("DEBUG file_id:", self.input_filename)
    
         
            bc = Blockchain()

            file_id =  filename
            root_hash = self.root_hash 
            commitment_hash_int = self.commitment_hash

            

            exists = bc.file_Exists(file_id)
          

            if exists == False:
                bc.register_file(file_id, root_hash, commitment_hash_int)
                # print("Registered initial version")
            else:
                bc.update_file(file_id, root_hash, commitment_hash_int)
                # print(f"Updated to version { bc.get_latest_version(file_id)}")
        
           
            # bc.register_root(file_id, root_hash, commitment_hash_int)
            # bc.get_status(file_id) 
            # print("IoT root hash + commitment hash registered on blockchain")
            
            return True
            
        except Exception as e:
            print(f"\n Error in workflow: {e}")
            return False

def main():

    filename = input("Enter filename (press Enter for 'input.txt'): ").strip()
   
    if not filename:
        raise ValueError("CRITICAL ERROR: No filename received from master script!")
    print(f"Using file: {filename}")
    device = SimpleIIoTDevice()
    device.run_complete_workflow(filename)

    # Example dynamic operation
    # device.modify_chunk(0, [1, 2, 3, 4])
    # device.upload_data()


if __name__ == "__main__":
    main()
