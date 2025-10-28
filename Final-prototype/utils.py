"""
Simplified Cryptographic Utilities for IIoT Cloud Storage Verification
====================================================================

This module provides lightweight implementations of:
- Homomorphic Hash Function (HHF)
- Polynomial operations
- Basic cryptographic primitives

All operations use small numbers to fit in standard Python datatypes.
"""

import hashlib
import random

# === GLOBAL PARAMETERS ===
P = 97      # Small prime modulus
G = 5       # Generator of multiplicative group mod P
PSI = 13    # Default secret key (small integer)

# === HOMOMORPHIC HASH FUNCTION ===
def HHF(x):
    """
    Homomorphic Hash Function: H = g^x mod p

    Args:
        x (int): Input value

    Returns:
        int: Hash value satisfying HHF(a) * HHF(b) mod p = HHF(a + b)
    """
    return pow(G, x % (P-1), P)

def verify_homomorphic_property(a, b):
    """Verify HHF(a) * HHF(b) = HHF(a + b) mod p"""
    ha = HHF(a)
    hb = HHF(b)
    hab = HHF(a + b)
    return (ha * hb) % P == hab

# === POLYNOMIAL OPERATIONS ===
def eval_polynomial(coefficients, x, mod=P):
    """
    Evaluate polynomial P(x) = c0 + c1*x + c2*x^2 + ... mod p

    Args:
        coefficients (list): Polynomial coefficients [c0, c1, c2, ...]
        x (int): Evaluation point
        mod (int): Modulus

    Returns:
        int: P(x) mod p
    """
    result = 0
    x_power = 1
    x= x % mod

    for coeff in coefficients:
        result = (result + coeff * x_power) % mod
        x_power = (x_power * x) % mod

    return result

def create_file_polynomial(data_blocks):
    """
    Create polynomiimport oqs
from config import PQC_SIGal from file data blocks
    P(x) = block[0] + block[1]*x + block[2]*x^2 + ...

    Args:
        data_blocks (list): File data blocks

    Returns:
        list: Polynomial coefficients
    """
    return data_blocks

# === HOMOMORPHIC TAG GENERATION ===
def create_homomorphic_tag(file_blocks, secret_key=PSI):
    """
    Create homomorphic tag from file blocks using polynomial commitment

    Args:
        file_blocks (list): List of file data blocks
        secret_key (int): Secret key for polynomial evaluation

    Returns:
        int: Homomorphic tag
    """
    # Create polynomial from file blocks
    polynomial_coeffs = create_file_polynomial(file_blocks)

    # Evaluate polynomial at secret point
    poly_eval = eval_polynomial(polynomial_coeffs, secret_key, P)

    # Create homomorphic tag
    tag = HHF(poly_eval)

    return tag

# === UTILITY FUNCTIONS ===
def simple_hash(data):
    """Simple hash function for Merkle tree nodes"""
    if isinstance(data, (int, float)):
        data = str(data)
    elif isinstance(data, list):
        data = ''.join(map(str, data))

    return int(hashlib.sha256(data.encode()).hexdigest()[:8], 16) % P


def process_file_to_blocks(file_data, block_size=4):
    """
    Convert file data to small integer blocks

    Args:
        file_data (str or bytes): Input file data
        block_size (int): Number of blocks per chunk

    Returns:
        list: List of small integer blocks
    """
    if isinstance(file_data, str):
        file_data = file_data.encode()

    # Convert bytes to small integers
    blocks = []
    for byte in file_data[:block_size]:
        # Keep blocks small (0-20 range)
        blocks.append(byte % 21)

    # Pad if necessary
    while len(blocks) < block_size:
        blocks.append(0)

    return blocks

# === PSEUDO-RANDOM FUNCTIONS ===
def pseudo_random_permutation(seed, index):
    """Simple pseudo-random permutation"""
    random.seed(seed + index)
    return random.randint(1, 100) % 20  # Keep small


def pseudo_random_function(seed, index):
    """Simple pseudo-random function"""
    random.seed(seed * 2 + index)
    return random.randint(1, 100) % 10  # Keep small

# === VALIDATION FUNCTIONS ===
def validate_parameters():
    """Validate that our parameters work correctly"""
    print(f"Parameters: P={P}, G={G}, PSI={PSI}")

    # Test homomorphic property
    test_vals = [(3, 7), (1, 5), (0, 2)]
    for a, b in test_vals:
        result = verify_homomorphic_property(a, b)
        print(f"HHF({a}) * HHF({b}) = HHF({a+b}): {result}")

    # Test polynomial evaluation
    coeffs = [3, 2, 1]  # 3 + 2x + x^2
    x = 5
    result = eval_polynomial(coeffs, x)
    expected = (3 + 2*5 + 1*25) % P
    print(f"Polynomial evaluation: {result} == {expected}: {result == expected}")

    return True


if __name__ == "__main__":
    print("IIoT Crypto Utilities - Validation")
    print("=" * 40)
    validate_parameters()