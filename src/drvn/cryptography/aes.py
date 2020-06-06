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
