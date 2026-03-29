# Major-Project
There are two schemes
1) Scheme 1 - Semi Decentralized Version(SDV)
2) Scheme 2 - Fully Decentralized Version(FDV)

To run both schemes, first clone the repository.
## SDV
```
cd Blockchain_integrated_Scheme1_final

```
Deploy the Storage_verification_dd.sol smart contract and change the ABI and address in the file contract_info_3.json

```
python scriptone.py
python scripttwo.py
```

To check data dynamics
```
python manage_files.py
```

To run time benchmarking
```
python benchmark_performance.py
```

To run overhead benchmarking
```
python measure_overhead_blockchain.py
```

## FDV
```
cd Blockchain_integrated_Scheme2_final

```
Deploy the Storage_Verification.sol smart contract and change the ABI and address in the file contract_info.json

```
python scriptone_old.py
python scripttwo_old.py
```

To check data dynamics
```
python manage_files.py
```

To run time benchmarking
```
python benchmark.py
```

To run overhead benchmarking
```
python overhead_analyser.py
```
