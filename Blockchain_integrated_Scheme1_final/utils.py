import hashlib

P = 97     
G = 5       

def pedersen_commit(m, r, params):
    p, g, h = params["p"], params["g"], params["h"]
    return (pow(g, m, p) * pow(h, r, p)) % p

def HHF(x):
    return pow(G, x % (P-1), P)


def pseudo_random_permutation(seed, index, mod):
    data = f"{seed}+{index}".encode()
    return int(hashlib.sha3_512(data).hexdigest(), 16) % mod


def pseudo_random_function(seed, index, mod):
    data = f"{seed}-{index}".encode()
    return int(hashlib.sha3_512(data).hexdigest(), 16) % mod
