import os
from web3 import Web3
import json

def int_to_bytes32(x: int) -> bytes:
    if not isinstance(x, int):
        raise TypeError("Value must be int")

    if x < 0 or x >= 2**256:
        raise ValueError("Value out of bytes32 range")

    b = x.to_bytes(32, byteorder="big")
    assert len(b) == 32
    return b


class Blockchain:
    def __init__(
        self,
        provider_url="http://127.0.0.1:7545",  # Ganache
        contract_info_path="contract_info.json"
    ):
        # Connect to blockchain
        self.w3 = Web3(Web3.HTTPProvider(provider_url))
        assert self.w3.is_connected(), "Blockchain not connected"

        # Load deployed contract info
        with open(contract_info_path, "r") as f:
            info = json.load(f)

        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(info["address"]),
            abi=info["abi"]
        )

        self.w3.eth.default_account = self.w3.eth.accounts[0]


    def register_file(self, human_name, unique_id, root_hash, comm_hash, commitments):
        # Load params...
        with open("zk_params.json", "r") as f:
            params = json.load(f)
        zk_vals = [params['p'], params['q'], params['g'], params['h']]

        # Convert bytes...
        root_bytes = bytes.fromhex(root_hash.replace('0x', ''))
        comm_bytes = bytes.fromhex(comm_hash.replace('0x', ''))

        # Call the UPDATED Solidity function
        print(f"   >>> Sending TX: Name={human_name}, ID={unique_id}")
        tx = self.contract.functions.registerFile(
            human_name,  
            unique_id,  
            root_bytes,
            comm_bytes,
            commitments,
            zk_vals
        ).transact()
        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        self.save_gas_timing("REGISTER_GAS", receipt.gasUsed)
        return receipt


    def verify_trustless_on_chain(self, unique_id, all_leaf_tags, all_proof_hashes, all_leaf_counts, all_sigmas, m_sum, r_sum, indices, coefficients,z,proof_value):
            """
            Submits multiple Merkle proofs and aggregated ZK data in one transaction.
            """
            try:
                # 1. Convert ALL leaf tags to bytes32
                formatted_leaf_tags = [self.w3.to_bytes(hexstr=str(tag)) for tag in all_leaf_tags]
                
                # 2. Convert ALL proof paths (nested lists) to bytes32
                formatted_proof_hashes = []
                for path in all_proof_hashes:
                    formatted_proof_hashes.append([self.w3.to_bytes(hexstr=str(h)) for h in path])
                if isinstance(proof_value, str):
                    if not proof_value.startswith('0x'):
                        proof_value = '0x' + proof_value
                    formatted_proof_value = self.w3.to_bytes(hexstr=proof_value)
                else:
                    formatted_proof_value = proof_value

                # 3. Call the UPDATED Solidity function with array parameters
                print(f" Submitting multi-chunk verification for {unique_id}...")
                tx = self.contract.functions.verifyTrustless(
                    unique_id,
                    formatted_leaf_tags,       # Array: bytes32[]
                    formatted_proof_hashes,    # Array: bytes32[][]
                    all_leaf_counts,           # Array: uint256[][]
                    all_sigmas,                # Array: uint8[][]
                    m_sum,                     # uint256
                    r_sum,                     # uint256
                    indices,                   # uint256[]
                    coefficients,               # uint256[]
                    z,
                    formatted_proof_value
                ).transact()

                receipt = self.w3.eth.wait_for_transaction_receipt(tx)
                print(f"   TX Hash: {tx.hex()}")
                self.save_gas_timing("VERIFY_GAS", receipt.gasUsed)
                return receipt

            except Exception as e:
                print(f" Blockchain multi-verification failed: {e}")
                return None
            
    def get_status(self, file_id: str) -> bool:
        return self.contract.functions.getStatus(file_id).call()

    
    def save_gas_timing(self, label, gas_used):
        print(f"   {label}: {gas_used} gas")
        gas_fn = "gas_timings.json"
        data = {}
        if os.path.exists(gas_fn):
            with open(gas_fn, 'r') as f:
                data = json.load(f)
        
        data[label] = gas_used
        with open(gas_fn, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_file_history(self, human_name):
        """Fetches the list of version IDs for a given filename."""
        try:
            # Call the View function (No Gas cost)
            history = self.contract.functions.getHistory(human_name).call()
            return history
        except Exception as e:
            print(f"Error fetching history: {e}")
            return []

    def delete_file(self, human_name):
        """Marks the file as deleted on the blockchain."""
        try:
            print(f"Deleting file: {human_name}...")
            tx = self.contract.functions.deleteFile(human_name).transact()
            receipt = self.w3.eth.wait_for_transaction_receipt(tx)
            print(f"File marked as DELETED. Tx Hash: {receipt.transactionHash.hex()}")
            return True
        except Exception as e:
            print(f"Error deleting file: {e}")
            return False

    def is_file_deleted(self, unique_id):
        """Checks if a specific version ID is marked as deleted."""
        try:
            # Returns True if deleted, False if active
            return self.contract.functions.isFileDeleted(unique_id).call()
        except Exception as e:
            print(f"Error checking status: {e}")
            return False