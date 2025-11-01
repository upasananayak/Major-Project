import random


def is_prime(n, k=40):
    if n < 2:
        return False
    
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p

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


def generate_pedersen_params(bits=128):
    while True:
        q = random.getrandbits(bits)
        q |= 1  
        p = 2 * q + 1
        if is_prime(q) and is_prime(p):
            break

    while True:
        g = random.randrange(2, p - 1)
        if pow(g, q, p) == 1 and pow(g, 2, p) != 1:
            break

    x = random.randrange(2, q - 1)
    h = pow(g, x, p)

    print(f"Generated ZK Parameters:")
    print(f" p (bits): {p.bit_length()}, q (bits): {q.bit_length()}")
    print(f" p: {p}")
    print(f" q: {q}")
    print(f" g: {g}")
    print(f" h: {h}")
    return {"p": p, "q": q, "g": g, "h": h}

if __name__ == "__main__":
    params = generate_pedersen_params()
    import json
    with open("zk_params.json", "w") as f:
        json.dump({k: int(v) for k, v in params.items()}, f)
    print("Wrote zk_params.json")