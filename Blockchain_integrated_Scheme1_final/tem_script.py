from web3 import Web3
import json

w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
print("Connected:", w3.is_connected())

with open("contract_info.json") as f:
    info = json.load(f)

contract = w3.eth.contract(address=info["address"], abi=info["abi"])
w3.eth.default_account = w3.eth.accounts[0]

file_id = "test_file"
root = (123).to_bytes(32, "big")

tx = contract.functions.registerRoot(file_id, root).transact()
receipt = w3.eth.wait_for_transaction_receipt(tx)

print("SUCCESS, status:", receipt.status)
