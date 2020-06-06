import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import drvn.cryptography.utils as utils


def encrypt_ebc(plaintext, key):
    cipher_obj = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    )
    encryptor = cipher_obj.encryptor()

    cipher = encryptor.update(plaintext) + encryptor.finalize()
    return cipher


def decrypt_ebc(cipher, key):  # TODO: rename cipher to ciphertext
    cipher_obj = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    )
    decryptor = cipher_obj.decryptor()

    plaintext = decryptor.update(cipher) + decryptor.finalize()
    return plaintext


def encrypt_cbc(plaintext, key, iv, block_size=16):
    ciphertext = bytearray()

    i = 0
    j = block_size
    v = iv
    while i < len(plaintext):
        plaintext_block = plaintext[i:j]
        plaintext_block_xored = utils.fixed_xor(v, plaintext_block)
        ciphertext_block = encrypt_ebc(plaintext_block_xored, key)

        ciphertext += ciphertext_block
        v = ciphertext_block
        i += block_size
        j += block_size

    return ciphertext


def decrypt_cbc(ciphertext, key, iv, block_size=16):
    plaintext = bytearray()

    i = 0
    j = block_size
    v = iv
    while i < len(ciphertext):
        ciphertext_block = ciphertext[i:j]
        decrypted_block_xor = decrypt_ebc(ciphertext_block, key)
        decrypted_block = utils.fixed_xor(v, decrypted_block_xor)
        plaintext += decrypted_block

        v = ciphertext_block
        i += block_size
        j += block_size

    return bytes(plaintext)


def detect_mode(ciphertext) -> str:
    """
    Looks for recurring 16 bytes in the ciphertext.
    If recurring 16 bytes are found the cihpertext is likely
    to have been encrypted in ecb mode.
    """
    blocks = set()
    block_size = 16
    i = 0
    j = block_size

    while j <= len(ciphertext):
        block = ciphertext[i:j]

        if block in blocks:
            return "ecb"

        blocks.add(block)
        i += block_size
        j += block_size

    return "unknown"


def generate_random_aes_key():
    byte_list = []
    for _ in range(0, 16):
        random_byte = random.randint(0, 255)
        byte_list.append(random_byte)
    key = bytes(byte_list)
    return key
