"""
Implement Diffie-Hellman
"""


# p = 37
# g = 5
# a = randomint mod p

# A = (g**a) % p # public key
# B = (g**b) % p # public key

# s = (B**a) % p # session key
# s = (A**b) % p # this is equivalent

import random
import logging
import hashlib

import drvn.cryptography.math as math


def run_challenge():
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    g = 2

    a = random.randint(0, p - 1)
    A = math.modexp(g, a, p)

    b = random.randint(0, p - 1)  # B = g**b % p
    B = math.modexp(g, b, p)  # A = g**a % p

    s = math.modexp(B, a, p)  # (g**b % p) ** a % p = (g**b)**a % p
    s2 = math.modexp(A, b, p)
    assert s == s2

    logging.info(f"s: {s}")

    num_bytes = (s.bit_length() + 7) // 8
    h = hashlib.sha256()
    h.update(s.to_bytes(num_bytes, "big"))
    hash = h.digest()
    logging.info(f"Session key: {hash.hex()}")
