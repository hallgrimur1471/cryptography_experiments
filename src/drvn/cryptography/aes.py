import random

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import drvn.cryptography.utils as utils


def encrypt_ebc(plaintext, key, add_padding=True):
    cipher_obj = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    )
    encryptor = cipher_obj.encryptor()

    if add_padding:
        plaintext = utils.add_pkcs7_padding(plaintext)

    cipher = encryptor.update(plaintext) + encryptor.finalize()
    return cipher


def decrypt_ebc(
    cipher, key, remove_padding=True
):  # TODO: rename cipher to ciphertext
    cipher_obj = Cipher(
        algorithms.AES(key), modes.ECB(), backend=default_backend()
    )
    decryptor = cipher_obj.decryptor()

    plaintext = decryptor.update(cipher) + decryptor.finalize()

    if remove_padding:
        plaintext = utils.remove_pkcs7_padding(plaintext)

    return plaintext


def encrypt_cbc(plaintext, key, iv, block_size=16, add_padding=True):
    if add_padding:
        plaintext = utils.add_pkcs7_padding(plaintext)

    ciphertext = bytearray()

    i = 0
    j = block_size
    v = iv
    while i < len(plaintext):
        plaintext_block = plaintext[i:j]
        plaintext_block_xored = utils.fixed_xor(v, plaintext_block)
        ciphertext_block = encrypt_ebc(
            plaintext_block_xored, key, add_padding=False
        )

        ciphertext += ciphertext_block
        v = ciphertext_block
        i += block_size
        j += block_size

    return ciphertext


def decrypt_cbc(ciphertext, key, iv, block_size=16, remove_padding=True):
    plaintext = bytearray()

    i = 0
    j = block_size
    v = iv
    while i < len(ciphertext):
        ciphertext_block = ciphertext[i:j]
        decrypted_block_xor = decrypt_ebc(
            ciphertext_block, key, remove_padding=False
        )
        decrypted_block = utils.fixed_xor(v, decrypted_block_xor)
        plaintext += decrypted_block

        v = ciphertext_block
        i += block_size
        j += block_size

    if remove_padding:
        plaintext = utils.remove_pkcs7_padding(plaintext)

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

        # Converting from bytearray to bytes because
        # bytearray is not hashable
        block = bytes(block)

        if block in blocks:
            return "ecb"

        blocks.add(block)
        i += block_size
        j += block_size

    return "unknown"


def generate_random_aes_key():
    return utils.generate_random_bytes(16)


def encryption_oracle(plaintext):
    prefix_size = random.randint(5, 10)
    prefix = utils.generate_random_bytes(prefix_size)

    suffix_size = random.randint(5, 10)
    suffix = utils.generate_random_bytes(suffix_size)

    plaintext_modified = prefix + plaintext + suffix

    key = generate_random_aes_key()

    if random.randint(0, 1) == 1:
        ciphertext = encrypt_ebc(plaintext_modified, key)
    else:
        iv = utils.generate_random_bytes(16)
        ciphertext = encrypt_cbc(plaintext_modified, key, iv)

    return ciphertext
