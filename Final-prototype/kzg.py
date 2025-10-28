"""
Mini-KZG: CORRECTED Simplified KZG Polynomial Commitment
======================================================
This implements the actual KZG algorithm structure using small numbers
"""

import random
from utils import P, G, PSI, eval_polynomial

class MiniKZG:
    def __init__(self, max_degree=4):
        self.max_degree = max_degree
        self.secret_s = PSI  # Our small secret (13)
        self.public_params = self._setup()
    
    def _setup(self):
        """
        KZG Setup: Generate public parameters {g^(s^i)} for i=0..n
        """
        public_params = []
        #s_power = 1  # s^0 = 1
        
        for i in range(self.max_degree + 1):
            # g^(s^i) mod P
            exp = pow(self.secret_s, i, P)
            param = pow(G, exp, P)
            public_params.append(param)

        
        return public_params
    
    def commit(self, polynomial_coeffs):
        """
        KZG Commitment: C = ∏(g^(s^i))^(coeff_i) = g^P(s)
        """
        commitment = 1  # Identity element
        
        for i, coeff in enumerate(polynomial_coeffs):
            if i >= len(self.public_params):
                break
                
            # (g^(s^i))^coeff = g^(coeff * s^i)
            term = pow(self.public_params[i], coeff, P)
            
            # Multiply into commitment: C = C * term
            commitment = (commitment * term) % P
        
        return commitment
    
    def create_witness(self, polynomial_coeffs, z, y):
        """
        KZG Witness Creation: π = g^h(s) where h(x) = (P(x) - y)/(x - z)
        """
        # Compute h(x) = (P(x) - y) / (x - z) using proper polynomial division
        h_coeffs = self._compute_quotient_polynomial_correct(polynomial_coeffs, z, y)
        
        # Commit to h(x) to get witness π = g^h(s)
        witness = self.commit(h_coeffs)
        return witness, h_coeffs
    
    def verify_evaluation(self, commitment, z, y, witness):
        """
        KZG Verification: Check if P(z) = y
        Real KZG: e(C, g) = e(π, g^s - g^z) * e(g, g)^y
        Our simplified version: C = π^(s-z) * g^y (mod P)
        """
        # Calculate g^(s-z) mod P
        s_minus_z = (self.secret_s - z) % (P - 1)
        g_s_minus_z = pow(G, s_minus_z, P)
        
        # Calculate π^(s-z) mod P  
        witness_powered = pow(witness, s_minus_z, P)
        
        # Calculate g^y mod P
        g_y = pow(G, y, P)
        
        # Check: C = π^(s-z) * g^y mod P
        right_side = (witness_powered * g_y) % P
        
        return commitment == right_side
    
    def _compute_quotient_polynomial_correct(self, poly_coeffs, z, y):
        """
        Compute h(x) = (P(x) - y) / (x - z) using CORRECT polynomial division
        """
        # First verify that P(z) = y
        p_at_z = eval_polynomial(poly_coeffs, z, P)
        if p_at_z != y:
            raise ValueError(f"P(z) ≠ y: P({z}) = {p_at_z}, y = {y}")
        
        # Perform synthetic division of (P(x) - y) by (x - z)
        # Since P(z) = y, we know (x - z) divides (P(x) - y)
        
        # Create polynomial P(x) - y
        adjusted_poly = poly_coeffs.copy()
        adjusted_poly[0] = (adjusted_poly[0] - y) % P
        
        # Synthetic division by (x - z)
        # For polynomial division by (x - z), we use synthetic division
        n = len(adjusted_poly)
        quotient = [0] * (n - 1) if n > 1 else [0]
        
        if n == 1:
            # Constant polynomial case
            quotient = [0]
        else:
            # Synthetic division algorithm
            quotient[n-2] = adjusted_poly[n-1]  # Leading coefficient
            
            for i in range(n-3, -1, -1):
                quotient[i] = (adjusted_poly[i+1] + quotient[i+1] * z) % P
        
        return quotient

# === INTEGRATION WITH OUR EXISTING SYSTEM ===

def create_kzg_homomorphic_tag(file_blocks, secret_key=PSI):
    """
    Create homomorphic tag using CORRECTED Mini-KZG commitment
    """
    # Initialize Mini-KZG system
    kzg = MiniKZG(max_degree=len(file_blocks))
    
    # Create polynomial from file blocks
    polynomial_coeffs = file_blocks
    
    # KZG Commitment
    commitment = kzg.commit(polynomial_coeffs)
    
    # Apply homomorphic hash to get final tag
    from utils import HHF
    tag = HHF(commitment)
    
    return tag, commitment, kzg

def demonstrate_kzg_workflow():
    """Show the complete KZG workflow with CORRECTED verification"""
    print("CORRECTED Mini-KZG Demonstration")
    print("=" * 35)
    
    # Sample file data blocks  
    file_blocks = [3, 7, 2, 5]  # P(x) = 3 + 7x + 2x² + 5x³
    
    # Create KZG tag
    tag, commitment, kzg = create_kzg_homomorphic_tag(file_blocks)
    
    print(f"File blocks: {file_blocks}")
    print(f"Secret s: {kzg.secret_s}")
    print(f"Public params: {kzg.public_params}")
    print(f"KZG Commitment: {commitment}")
    print(f"Homomorphic Tag: {tag}")
    
    # Demonstrate evaluation and witness
    z = 2  # Evaluation point
    y = eval_polynomial(file_blocks, z, P)  # P(2)
    
    print(f"\nEvaluation at z={z}: P({z}) = {y}")
    
    # Create witness 
    try:
        witness, h_coeffs = kzg.create_witness(file_blocks, z, y)
        print(f"KZG Witness: {witness}")
        print(f"Quotient polynomial h(x): {h_coeffs}")
        
        # Verify 
        is_valid = kzg.verify_evaluation(commitment, z, y, witness)
        print(f"Verification result: {is_valid}")
        
        # Test with different evaluation point
        z2 = 3
        y2 = eval_polynomial(file_blocks, z2, P)
        print(f"\nTesting with z={z2}: P({z2}) = {y2}")
        witness2, h_coeffs2 = kzg.create_witness(file_blocks, z2, y2)
        is_valid2 = kzg.verify_evaluation(commitment, z2, y2, witness2)
        print(f"Verification result for z={z2}: {is_valid2}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    return tag, commitment

if __name__ == "__main__":
    demonstrate_kzg_workflow()