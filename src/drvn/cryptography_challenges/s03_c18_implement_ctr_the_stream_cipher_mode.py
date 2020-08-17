"""
Implement CTR, the stream cipher mode
"""

import base64
import logging

import drvn.cryptography.aes as aes


def run_challenge():
    ciphertext = base64.b64decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/"
        + "2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    )
    key = b"YELLOW SUBMARINE"
    nonce = 0
    plaintext = aes.decrypt_ctr(ciphertext, key, nonce)

    logging.info(
        f"\nThe ciphertext:\n{base64.b64encode(ciphertext)}\nwas decrypted "
        + f"using AES-CTR with {key=} and {nonce=} to the "
        + f"plaintext:\n{plaintext}"
    )

    resulting_ciphertext = aes.encrypt_ctr(plaintext, key, nonce)
    logging.info(
        f"\nThe plaintext:\n{plaintext}\nwas encrypted "
        + f"using AES-CTR with {key=} and {nonce=} to the "
        + f"ciphertext:\n{base64.b64encode(resulting_ciphertext)}"
    )
