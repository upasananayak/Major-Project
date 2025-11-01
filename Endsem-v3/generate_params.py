# # generate_params.py
# import json
# from pq_utils import demo_group_params

# params = demo_group_params()  # expensive; run once
# with open("zk_params.json", "w") as f:
#     json.dump({k: int(v) for k, v in params.items()}, f)
# print("Wrote zk_params.json (store this securely and reuse).")
# import random

# def generate_pedersen_params():
#     # 1. Pick a safe prime p = 2q + 1
#     while True:
#         q = random.getrandbits(127)
#         p = 2 * q + 1
#         if is_prime(q) and is_prime(p):
#             break

#     # 2. Choose generator g of subgroup of order q
#     # pick random g until g^q mod p == 1 and g != 1
#     while True:
#         g = random.randrange(2, p - 1)
#         if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
#             break

#     # 3. Choose a different generator h = g^x for random x
#     x = random.randrange(2, q - 1)
#     h = pow(g, x, p)

#     return {"p": p, "q": q, "g": g, "h": h}
import random

# -----------------------------
# Fast primality test (Miller–Rabin)
# -----------------------------
def is_prime(n, k=40):
    """Miller–Rabin primality test."""
    if n < 2:
        return False
    # Small primes for quick elimination
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# -----------------------------
# Safe-prime Pedersen parameters
# -----------------------------
def generate_pedersen_params(bits=128):
    """
    Generate a safe prime p = 2q + 1 and subgroup generators g, h.
    p ≈ 2 * q + 1 where both p and q are prime.
    """
    print("⏳ Generating safe prime parameters...")
    while True:
        q = random.getrandbits(bits)
        q |= 1  # make sure q is odd
        p = 2 * q + 1
        if is_prime(q) and is_prime(p):
            break

    # Find generator g of subgroup of order q mod p
    while True:
        g = random.randrange(2, p - 1)
        if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
            break

    # Derive a second independent generator h = g^x mod p
    x = random.randrange(2, q - 1)
    h = pow(g, x, p)

    print(f"✅ Generated safe prime group:")
    print(f" p (bits): {p.bit_length()}, q (bits): {q.bit_length()}")
    print(f" g: {g}")
    print(f" h: {h}")
    return {"p": p, "q": q, "g": g, "h": h}

if __name__ == "__main__":
    params = generate_pedersen_params()
    import json
    with open("zk_params_test.json", "w") as f:
        json.dump({k: int(v) for k, v in params.items()}, f)
    print("Wrote zk_params_test.json (store this securely and reuse).")