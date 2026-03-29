import os
import json
from config import SERVER_KEM_PUB
from utils import HHF
from pq_utils import kem_encapsulate, encrypt_with_shared_key, simple_hash
import base64
import random
from utils import pedersen_commit
import hashlib
import time
from blockchain import Blockchain

def int_to_bytes32(x: int) -> bytes:
    if not isinstance(x, int):
        raise TypeError("root_hash must be int")

    if x < 0 or x >= 2**256:
        raise ValueError("root_hash out of bytes32 range")

    b = x.to_bytes(32, byteorder="big")

    assert len(b) == 32
    return b

BLOCKS_PER_CHUNK = 30    # blocks per chunk 
BLOCK_SIZE_BITS = 8    # Each block is 8-bit integer

class SimpleIoTDevice:
    def __init__(self):
        # print(" Initializing Simple IoT Device")

        # print(f"   Blocks per chunk: {BLOCKS_PER_CHUNK}")
        # print(f"   Block size: {BLOCK_SIZE_BITS}-bit integers")

        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)
        # print("ZK PARAMS loaded")

        assert hasattr(self, "ZK_PARAMS"), "ZK_PARAMS not loaded!"


    def process_file(self, filename):
        print(f"\n File Processing - {filename}")
        
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                f.write("Hello IoT! Test data for storage verification.")
            # print(f"   Created sample file: {filename}")
        
        with open(filename, 'rb') as f:
            file_data = f.read()
        
        # print(f"   File size: {len(file_data)} bytes")

        self.chunks = self._file_to_chunks(file_data)

        # print(f"   Created {len(self.chunks)} chunks")
        

        # for i, chunk in enumerate(self.chunks):
        #     # print(f"   Chunk {i}: {chunk}")
        
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

    def generate_homomorphic_tags(self, chunks):
        # print(f"   Processing {len(chunks)} chunks (Checking Cache...)")
        
        cache = self.load_cache()
        new_cache = {}
        
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
            
            # 1. Save Raw Commitment (Big Integer) for the Blockchain Registry
            commitments.append(comm)
            
            # 2. Save Hashed Tag (HHF) for the Merkle Tree
            tag = HHF(comm) 
            tags.append(tag)

            random_values.append(r)
            
            # Store Raw commitment in polynomial list (Verification needs the raw values to check proof)
            self.polynomial_commitments.append({
                  "coeffs": chunk_list,                  
                  "r": r,
                  "commitment": comm, 
                  "m_i": m_scalar                      
            })
            
            new_cache[chunk_hash] = {'r': r, 'commitment': comm}

        self.save_cache(new_cache)
        
        # print(f"   [EFFICIENCY REPORT]")
        # print(f"   Reused from Cache : {reused_count}")
        # print(f"   Newly Computed    : {len(chunks) - reused_count}")

        # Save to class instance correctly
        self.commitments = commitments       
        self.homomorphic_tags = tags         
        
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
        # print(f"Generated PQ signature keypair for IoT device")

        current_level = leaf_hashes[:]
        while len(current_level) > 1:
            next_level = []
            z*=2
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left

                parent = simple_hash(None, types=['uint256', 'bytes32', 'bytes32'], values=[z, left, right])
                # print(f"   h({z}||{left}||{right}) = {parent}")
                next_level.append(parent)
            current_level = next_level
        
        return current_level[0]

    def compute_commitment_hash(self):
        commitment_concat = "|".join(map(str, self.commitments)) + "|"

        self.commitment_hash = simple_hash(commitment_concat)

        # print(f"\n Commitment Hash (all chunks): {self.commitment_hash}")
        return self.commitment_hash
    
    def upload_data(self):
        # print(f"\n  Data Upload")
        
        current_file_id = getattr(self, 'unique_version_id', self.input_filename)
        
        # 1. Prepare Cloud Data
        cloud_data = {
            "input_file": current_file_id,
            "original_name": self.input_filename, 
            "random_values": [pc["r"] for pc in self.polynomial_commitments],
            "homomorphic_tags": self.homomorphic_tags,
            "metadata": {
                "num_chunks": len(self.chunks),
                "blocks_per_chunk": BLOCKS_PER_CHUNK,
            }
        }
        
        verifier_data = {
            "input_file": current_file_id,
            "original_name": self.input_filename,
            "root_hash": self.root_hash,
            "num_chunks": len(self.chunks),
            "blocks_per_chunk": BLOCKS_PER_CHUNK,
            "commitments": [pc["commitment"] for pc in self.polynomial_commitments]
        }
        
        # 3. Encrypt and Save
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
        
        with open("iot_to_cloud_dec.json", "w") as f:
            json.dump(cloud_data, f, indent=4)

        # print(f"   Data sent to cloud")
        # print(f"   Files created: iot_to_cloud.enc.json, iot_to_verifier.enc.json")
        
        return cloud_data, verifier_data
    
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
            # 1. Process File
            self.process_file(filename)
            
            # 2. Generate Tags 
            # The function now populates self.commitments (Raw) and self.homomorphic_tags (Hashed)
            self.generate_homomorphic_tags(self.chunks)  
            
            # --- IMPORTANT FIX ---
            # DO NOT write: self.homomorphic_tags = self.commitments
            # We want self.homomorphic_tags to remain HASHED (from the function above).
            
            # 3. Build Merkle Tree 
            # Uses self.homomorphic_tags (Hashed), so the Root matches Cloud Server logic.
            self.build_tag_imht()
            
            # 4. Compute Commitment Hash
            # Uses self.commitments (Raw), so the Contract gets the correct math data.
            self.compute_commitment_hash()
            
            # 5. Generate Version ID
            timestamp = int(time.time())
            self.unique_version_id = f"{filename}_v{timestamp}"
            
            # 6. Upload Data (This writes the JSONs)
            self.upload_data()
            
            # print("\n IoT Device Workflow Completed Successfully!")
            # print(f"DEBUG: Unique Version ID: {self.unique_version_id}")
    
            # 7. Blockchain Registration
            bc = Blockchain() 
            # print(" Registering file version on blockchain...")
            
            receipt = bc.register_file(
                human_name=filename,         
                unique_id=self.unique_version_id, 
                root_hash=self.root_hash, 
                comm_hash=self.commitment_hash, 
                # CRITICAL: Send RAW commitments to the Smart Contract
                commitments=self.commitments 
            )
            
            # print("IoT root hash + commitment hash registered on blockchain")
            return True
            
        except Exception as e:
            print(f"\n Error in workflow: {e}")
            import traceback
            traceback.print_exc()
            return False
def main():
    filename = input("Enter filename (press Enter for 'input.txt'): ").strip()
    if not filename:
        filename = "input.txt"
    print(f"Using file: {filename}")
    
    device = SimpleIoTDevice()
    success = device.run_complete_workflow(filename)
    
    if success:
        print("\n IoT Simulation completed successfully!")
        
    else:
        print("\n Simulation failed!")

if __name__ == "__main__":
    main()