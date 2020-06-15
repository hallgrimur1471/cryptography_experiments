import random
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import drvn.cryptography.utils as utils


# TODO: rename to encrypt_ecb
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


def encrypt_cbc(plaintext, key, iv, block_size=128, add_padding=True):
    block_size_bytes = block_size // 8
    if add_padding:
        plaintext = utils.add_pkcs7_padding(plaintext)

    ciphertext = bytearray()

    i = 0
    j = block_size_bytes
    v = iv
    while i < len(plaintext):
        plaintext_block = plaintext[i:j]
        plaintext_block_xored = utils.fixed_xor(v, plaintext_block)
        ciphertext_block = encrypt_ebc(
            plaintext_block_xored, key, add_padding=False
        )

        ciphertext += ciphertext_block
        v = ciphertext_block
        i += block_size_bytes
        j += block_size_bytes

    return ciphertext


def decrypt_cbc(ciphertext, key, iv, block_size=128, remove_padding=True):
    block_size_bytes = block_size // 8
    plaintext = bytearray()

    i = 0
    j = block_size_bytes
    v = iv
    while i < len(ciphertext):
        ciphertext_block = ciphertext[i:j]
        decrypted_block_xor = decrypt_ebc(
            ciphertext_block, key, remove_padding=False
        )
        decrypted_block = utils.fixed_xor(v, decrypted_block_xor)
        plaintext += decrypted_block

        v = ciphertext_block
        i += block_size_bytes
        j += block_size_bytes

    if remove_padding:
        plaintext = utils.remove_pkcs7_padding(plaintext)

    return bytes(plaintext)


def detect_mode(ciphertext, block_size=128) -> str:
    """
    Looks for recurring {block_size} bits in the ciphertext.
    If recurring {block_size} bits are found the cihpertext is likely
    to have been encrypted in ecb mode.
    """
    blocks = set()
    block_size_bytes = block_size // 8
    i = 0
    j = block_size_bytes

    while j <= len(ciphertext):
        block = ciphertext[i:j]

        # Converting from bytearray to bytes because
        # bytearray is not hashable
        block = bytes(block)

        if block in blocks:
            return "ecb"

        blocks.add(block)
        i += block_size_bytes
        j += block_size_bytes

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


def decrypt_ecb_encryption_with_prependable_plaintext(encrypt_func):
    cipher_block_size = determine_cipher_block_size_by_prependable_plaintext(
        encrypt_func
    )
    logging.info(f"Cipher has block size {cipher_block_size}")

    prefix = ("A" * 1000).encode()
    ciphertext = encrypt_func(prefix)
    cipher_mode = detect_mode(ciphertext, block_size=cipher_block_size)
    logging.info(f"Cipher is using '{cipher_mode}' mode")
    if cipher_mode != "ecb":
        raise RuntimeError("Unable to decrypt, cipher is not in ECB mode")

    ciphertext_length_no_prefix = len(encrypt_func(b""))
    logging.info(
        f"ciphertext length with no prefix: {ciphertext_length_no_prefix}"
    )
    prefix = bytes(("A" * ciphertext_length_no_prefix).encode())
    ciphertext = encrypt_func(prefix)
    # utils.print_ciphertext_blocks(ciphertext, block_size=cipher_block_size)

    block_size_bytes = cipher_block_size // 8
    block_i = (ciphertext_length_no_prefix // block_size_bytes) - 1
    logging.info(f"block_i: {block_i}")

    base_prefix = prefix[0:-1]
    known = b""
    for r in range(0, ciphertext_length_no_prefix):
        ciphertext = encrypt_func(base_prefix)
        target_block = utils.get_block(
            ciphertext, block_i, block_size=cipher_block_size
        )

        k = len(base_prefix) - 1
        for i in range(0, 256):
            byte_ = bytes([i])
            prefix = base_prefix + known + byte_
            ciphertext = encrypt_func(prefix)
            block = utils.get_block(
                ciphertext, block_i, block_size=cipher_block_size
            )
            # print(i, block.hex(), target_block.hex())
            if block == target_block:
                known += byte_
                base_prefix = base_prefix[0:-1]
                # base_prefix[k] = i
                # k -= 1
                # base_prefix = base_prefix[1:]
                print(base_prefix + known)
                break

    print(known)
    known = utils.remove_pkcs7_padding(known)
    print(known.decode())

    # print(len(prefix))
    # prefix = prefix[0:-1]
    # print(len(prefix))
    # ciphertext = encrypt_func(prefix)
    # utils.print_ciphertext_blocks(ciphertext, block_size=cipher_block_size)
    # target_block = utils.get_block(
    #    ciphertext, block_i, block_size=cipher_block_size
    # )

    # base_prefix = prefix


def determine_cipher_block_size_by_prependable_plaintext(encrypt_func):
    """
    Determine block size of a cipher that has an encryption API like this:

    AES_ECB(attacker_controlled || unknown_plaintext, unknown_key)

    Args:
        encrypt_func (function): Wrapper to victim's encryption API.
            encrypt_func takes one bytes argument, prefix,  which will be
            prepended to the unknown plaintext before it's encrypted.
            encrypt_func returns the resulting ciphertext.
    Returns:
        cipher_block_size (int). Cipher block size in bits.
    """
    first_ciphertext_length = len(encrypt_func(b""))
    i = 1
    while True:
        prefix = ("A" * i).encode()
        next_ciphertext_length = len(encrypt_func(prefix))

        if next_ciphertext_length != first_ciphertext_length:
            cipher_block_size = (
                next_ciphertext_length - first_ciphertext_length
            ) * 8
            return cipher_block_size

        i += 1
