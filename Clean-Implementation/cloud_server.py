import base64
import hashlib
import json
import os
from config import SERVER_KEM_PUB, SERVER_KEM_SK
from pq_utils import decrypt_with_shared_key, encrypt_with_shared_key, kem_decapsulate, kem_encapsulate, simple_hash
from utils import pedersen_commit

class SimpleCloudServer:
    def __init__(self):

        print(" Initializing Simple Cloud Server")
        self.stored_data = None
        self.received_data = False

        with open("zk_params.json", "r") as _f:
            self.ZK_PARAMS = json.load(_f)
        
        assert hasattr(self, "ZK_PARAMS"), "ZK_PARAMS not loaded!"


    def load_data_from_iot(self, filename="iot_to_cloud_dec.json"):
        print(f"\n STEP 1: Loading Data from IoT Device")
        
        try:
            with open(filename, 'r') as f:
                self.stored_data = json.load(f)

            self.input_file = self.stored_data["input_file"]
            self.homomorphic_tags = self.stored_data["homomorphic_tags"]
            self.metadata = self.stored_data["metadata"]
            self.random_values = self.stored_data["random_values"]
            self.blocks_per_chunk = int(self.metadata.get("blocks_per_chunk", 4))

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
        print("\n Decrypting IoT to Cloud encrypted payload")

        if not os.path.exists(enc_filename):
            print(f"   Encrypted file not found: {enc_filename}")
            return False

        if not os.path.exists(SERVER_KEM_SK):
            print(f"   Server KEM secret not found: {SERVER_KEM_SK}.")
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

            print(f"   Decrypted payload written to: {out_filename}")
            self.stored_data = payload_json
            self.received_data = True
            return True
        
        except Exception as e:
            print(f"   Decryption failed: {e}")
            return False

    def receive_challenge(self, filename="challenge.json"):
        print(f"\n Receiving Challenge from Verifier")

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
        with open(filename, "rb") as f:
            data = f.read()

        chunks = []
        for i in range(0, len(data), self.blocks_per_chunk):
            chunk_bytes = data[i:i+self.blocks_per_chunk]
            chunk_blocks = [(b % 21) for b in chunk_bytes]
            while len(chunk_blocks) < self.blocks_per_chunk:
                chunk_blocks.append(0)
            chunks.append(chunk_blocks)
        return chunks

    def generate_zk_pedersen_proof(self, z, challenge_set):
        print("Generating ZK Pedersen Proof")
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
            Ci = pedersen_commit(m_i, r_i, self.ZK_PARAMS)

            m_sum = (m_sum + (a_i * m_i)) % q
            r_sum = (r_sum + (a_i * r_i)) % q
            C_agg = (C_agg * pow(Ci, a_i, p)) % p
            
        proof_value = hashlib.sha3_512(
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
        print("\n Generating ZK proofs for challenged chunks...")

        if not hasattr(self, "challenge_set"):
            print("   Error: Challenge not received!")
            return None
        self.file_chunks = self.read_file_chunks(stored_file)

        proof_obj = self.generate_zk_pedersen_proof(self.z, self.challenge_set)

        self.aai_data = {}

        for chunk_id, _ in self.challenge_set:
            aai_raw = self.generate_aai(chunk_id)  
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

        self.challenged_tags = {}
        for chunk_id, _ in self.challenge_set:
            self.challenged_tags[str(chunk_id)] = simple_hash(self.homomorphic_tags[chunk_id])
            print(f"   Challenged tag for chunk {chunk_id}: {self.challenged_tags[str(chunk_id)]}")


        tag_hashes = [simple_hash(str(tag)) for tag in self.homomorphic_tags]

        self.root, self.levels = self.build_merkle_tree_with_storage(tag_hashes)
        print(f"   Cloud Merkle Tree built successfully.")

        self.proof = {
            "aai_data": self.aai_data,
            "challenge_metadata": {
                "challenge_set": self.challenge_set,
                "z": self.z,
                "k1": self.k1,
                "k2": self.k2,
                "c": self.c
            },
            "challenged_tags": self.challenged_tags,
            "homomorphic_tags": self.homomorphic_tags,
            "zk_proofs": proof_obj,
            "cloud_root_hash": self.root
        }

        return self.proof
    
 
    def build_merkle_tree_with_storage(self, leaf_hashes):
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
        for level in self.levels[:-1]:  
            sibling_index = index ^ 1
            if sibling_index >= len(level):
                sibling_index = index 
            sibling_hash = level[sibling_index]
            direction = 0 if sibling_index < index else 1  
            aai_list.append((sibling_hash, direction))
            index = index // 2
        return aai_list

    def send_proof_to_verifier(self, filename="cloud_to_verifier.enc.json"):
        print(f"\n Sending Post-Quantum Hash-Based Proof to Verifier")

        if not hasattr(self, 'proof'):
            print("   Error: No proof generated! Run generate_proof() first.")
            return False

        proof_package = {
            "zk_proofs": self.proof.get("zk_proofs", []),
            "challenge_metadata": self.proof.get("challenge_metadata", {}),
            "aai_data": self.proof.get("aai_data", {}),
            "challenged_tags": self.proof.get("challenged_tags", {}),
            "cloud_root_hash": self.proof.get("cloud_root_hash", {})
        }

        proof_json = json.dumps(proof_package, indent=2).encode()

        if not os.path.exists(SERVER_KEM_PUB):
            raise FileNotFoundError(f"Server public key not found: {SERVER_KEM_PUB}.")
        
        with open(SERVER_KEM_PUB, "r") as f:
            server_pk = base64.b64decode(f.read().strip())

        ct, shared = kem_encapsulate(server_pk)
        proof_encrypted_payload = encrypt_with_shared_key(shared, proof_json)

        proof_out_obj = {
            "ct": base64.b64encode(ct).decode(),
            "enc_payload": base64.b64encode(proof_encrypted_payload).decode()
        }

        with open(filename, "w") as f:
            json.dump(proof_out_obj, f, indent=2)

        return True


    def run_complete_workflow(self):
        
        try:
            if os.path.exists("iot_to_cloud.enc.json"):
                if not self.decrypt_iot_payload():
                    return False
            else:
                print("   No encrypted payload found; will attempt to load iot_to_cloud.json directly.")

            if not self.load_data_from_iot():
                return False
            

            challenge_set = self.receive_challenge(filename="challenge.json")  
            if not challenge_set:
                return False
            
            proof = self.generate_proof(stored_file=self.input_file)
            if not proof:
                return False
            

            if not self.send_proof_to_verifier():
                return False
            
            print("\n Cloud Server Workflow Completed Successfully!")
            return True
            
        except Exception as e:
            print(f"\n Error in cloud server workflow: {e}")
            return False

def main():
    print("Starting Simple Cloud Server Simulation...")
    
    server = SimpleCloudServer()
    success = server.run_complete_workflow()
    
    if success:
        print("\n Ready for verifier to check the proof!")
    else:
        print("\n Cloud server failed!")

if __name__ == "__main__":
    main()