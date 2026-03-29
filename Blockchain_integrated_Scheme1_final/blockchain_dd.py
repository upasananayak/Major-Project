from web3 import Web3
import json
import os
# ---------- Helper: int -> bytes32 ----------
def int_to_bytes32(x: int) -> bytes:
    if not isinstance(x, int):
        raise TypeError("Value must be int")

    if x < 0 or x >= 2**256:
        raise ValueError("Value out of bytes32 range")

    return x.to_bytes(32, byteorder="big")


class Blockchain:
    def __init__(
        self,
        provider_url="http://127.0.0.1:7545",  # Ganache GUI
        contract_info_path="contract_info_3.json"
    ):
        self.w3 = Web3(Web3.HTTPProvider(provider_url))
        assert self.w3.is_connected(), "Blockchain not connected"

        with open(contract_info_path, "r") as f:
            info = json.load(f)

        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(info["address"]),
            abi=info["abi"]
        )

        self.w3.eth.default_account = self.w3.eth.accounts[0]
        self.metrics_file = "blockchain_tx_metrics.json"

    def _save_gas_metric(self, tx_name, receipt):
        """Helper to save gas used and input data size to a metrics file."""
        metrics = {}
        if os.path.exists(self.metrics_file):
            with open(self.metrics_file, "r") as f:
                metrics = json.load(f)
        
        # Capture gas used and the size of the input calldata
        metrics[tx_name] = {
            "gasUsed": receipt.gasUsed,
            "cumulativeGasUsed": receipt.cumulativeGasUsed,
            "status": receipt.status
        }
        
        with open(self.metrics_file, "w") as f:
            json.dump(metrics, f, indent=2)
    # ------------------------------------------------
    # registerFile(string fileId, bytes32 root, bytes32 commitment)
    # FIRST upload → version = 1
    # ------------------------------------------------
    def register_file(self, file_id: str, root_hash_int: int, commitment_hash_int: int):
        root_bytes32 = int_to_bytes32(root_hash_int)
        commitment_bytes32 = int_to_bytes32(commitment_hash_int)

        tx = self.contract.functions.registerFile(
            file_id, root_bytes32, commitment_bytes32
        ).transact()

        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        self._save_gas_metric("registerFile", receipt)
        return receipt

    # ------------------------------------------------
    # updateFile(string fileId, bytes32 root, bytes32 commitment)
    # Insert / Modify / Delete → NEW VERSION
    # ------------------------------------------------
    def update_file(self, file_id: str, root_hash_int: int, commitment_hash_int: int):
        root_bytes32 = int_to_bytes32(root_hash_int)
        commitment_bytes32 = int_to_bytes32(commitment_hash_int)

        tx = self.contract.functions.updateFile(
            file_id, root_bytes32, commitment_bytes32
        ).transact()

        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        self._save_gas_metric("updateFile", receipt)
        return receipt

    # ------------------------------------------------
    # submitVerification(string fileId, uint256 version,
    #                    bytes32 root, bytes32 commitment)
    # ------------------------------------------------
    def submit_verification(self, file_id: str, version: int, computed_root_int: int, computed_commitment_int: int):
        computed_root_bytes32 = int_to_bytes32(computed_root_int)
        computed_commitment_bytes32 = int_to_bytes32(computed_commitment_int)

        tx = self.contract.functions.submitVerification(
            file_id, version, computed_root_bytes32, computed_commitment_bytes32
        ).transact()

        receipt = self.w3.eth.wait_for_transaction_receipt(tx)
        self._save_gas_metric("submitVerification", receipt)
        return receipt

    # -------------------------
    # getLatestVersion(string)
    # -------------------------
    def get_latest_version(self, file_id: str) -> int:
        return self.contract.functions.getLatestVersion(file_id).call()

    def file_Exists(self,file_id:str) ->bool:
        return self.contract.functions.fileExists(file_id).call()
    # -------------------------
    # getLatestStatus(string)
    # -------------------------
    def get_latest_status(self, file_id: str) -> bool:
        return self.contract.functions.getLatestStatus(file_id).call()
    
    def get_latest_root_hash_int(self, file_id: str) -> int:
      
        if not isinstance(file_id, str):
            raise TypeError("file_id must be a string")

        root_bytes = self.contract.functions.getLatestRootWithVersion(
            file_id
        ).call()

        # bytes32 → int
        root_int = int.from_bytes(root_bytes, byteorder="big")

        return root_int
    def get_file_history(self, file_id: str):
        try:
            # Returns [1, 2, 3...] representing version numbers
            return self.contract.functions.getVersionHistory(file_id).call()
        except Exception as e:
            print(f"Error fetching history: {e}")
            return []

    def delete_file(self, file_id: str):
        try:
            tx = self.contract.functions.deleteFile(file_id).transact()
            receipt = self.w3.eth.wait_for_transaction_receipt(tx)
            self._save_gas_metric("deleteFile", receipt)
            return True
        except Exception as e:
            print(f"Error deleting: {e}")
            return False

    def is_file_deleted(self, file_id: str):
        # In Scheme 1, deletion is usually per file, not per version
        return self.contract.functions.isFileDeleted(file_id).call()