import random
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import drvn.cryptography.utils as utils


def encrypt_ecb(plaintext, key, add_padding=True):
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
        ciphertext_block = encrypt_ecb(
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
        ciphertext = encrypt_ecb(plaintext_modified, key)
    else:
        iv = utils.generate_random_bytes(16)
        ciphertext = encrypt_cbc(plaintext_modified, key, iv)

    return ciphertext


def decrypt_ecb_encryption_with_prependable_plaintext_1(encrypt_func):
    """
    Determine unknown_plaintext of a cipher that has an encryption API like this:

    AES_ECB(attacker_controlled || unknown_plaintext, unknown_key)

    Args:
        encrypt_func (function): Wrapper to victim's encryption API.
            encrypt_func takes one bytes argument, prefix,  which will be
            prepended to the unknown plaintext before it's encrypted.
            encrypt_func returns the resulting ciphertext.
    Returns:
        unknown_plaintext (bytes)
    """
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

    block_size_bytes = cipher_block_size // 8
    block_i = (ciphertext_length_no_prefix // block_size_bytes) - 1

    base_prefix = prefix[0:-1]
    plaintext = b""
    for _ in range(0, ciphertext_length_no_prefix):
        ciphertext = encrypt_func(base_prefix)
        target_block = utils.get_block(
            ciphertext, block_i, block_size=cipher_block_size
        )

        for i in range(0, 256):
            byte_ = bytes([i])
            prefix = base_prefix + plaintext + byte_
            ciphertext = encrypt_func(prefix)
            block = utils.get_block(
                ciphertext, block_i, block_size=cipher_block_size
            )
            if block == target_block:
                plaintext += byte_
                base_prefix = base_prefix[0:-1]
                print(base_prefix + plaintext)
                break

    plaintext = utils.remove_pkcs7_padding(plaintext)
    logging.info(f"Resulting plaintext:\n{plaintext.decode()}")

    return plaintext


def decrypt_ecb_encryption_with_injectable_plaintext(encrypt_func):
    """
    Determine unknown_plaintext of a cipher that has an encryption API like this:

    AES_ECB(unknown_fixed_prefix || attacker_controlled || unknown_plaintext,
            unknown_key)

    Args:
        encrypt_func (function): Wrapper to victim's encryption API.
            encrypt_func takes one bytes argument, attacker_controlled,
            which will be injected to the unknown plaintext before it's
            encrypted.
            encrypt_func returns the resulting ciphertext.
    Returns:
        unknown_plaintext (bytes)
    """
    # figure out cipher block size
    cipher_block_size = determine_cipher_block_size_by_prependable_plaintext(
        encrypt_func
    )
    logging.debug(f"Cipher has block size {cipher_block_size}")

    # figure out cipher mode
    user_input = ("A" * 1000).encode()
    ciphertext = encrypt_func(user_input)
    cipher_mode = detect_mode(ciphertext, block_size=cipher_block_size)
    logging.debug(f"Cipher is using '{cipher_mode}' mode")
    if cipher_mode != "ecb":
        raise RuntimeError("Unable to decrypt, cipher is not in ECB mode")

    # figure out fixed_prefix length, lets see how many 'B' we need to input to get
    # num_continuous identical ciphertext blocks
    prefix_length = figure_out_prefix_length(encrypt_func, cipher_block_size)
    logging.debug(f"'unknown_fixed_prefix' length is {prefix_length}")

    # figure out unkown_plaintext length
    block_size_bytes = cipher_block_size // 8
    prefix_filler_length = block_size_bytes - (prefix_length % block_size_bytes)
    user_input = ("A" * (prefix_length + prefix_filler_length)).encode()
    ciphertext = encrypt_func(user_input)
    plaintext_length = len(ciphertext) - (prefix_length + prefix_filler_length)

    # figure out unkown_plaintext bytes
    base_user_input = ("A" * (prefix_filler_length + plaintext_length)).encode()
    base_user_input = base_user_input[0:-1]  # leave room to edit 1 byte
    block_i = (
        (prefix_length + prefix_filler_length + plaintext_length)
        // block_size_bytes
    ) - 1
    known_plaintext = b""
    for _ in range(0, plaintext_length):
        ciphertext = encrypt_func(base_user_input)
        target_block = utils.get_block(
            ciphertext, block_i, block_size=cipher_block_size
        )
        for i in range(0, 256):
            byte_ = bytes([i])
            user_input = base_user_input + known_plaintext + byte_
            ciphertext = encrypt_func(user_input)
            block = utils.get_block(
                ciphertext, block_i, block_size=cipher_block_size
            )
            if block == target_block:
                known_plaintext += byte_
                base_user_input = base_user_input[0:-1]
                # print(base_user_input + plaintext)
                break

    plaintext = utils.remove_pkcs7_padding(known_plaintext)

    return plaintext


def figure_out_prefix_length(encrypt_func, cipher_block_size):
    """
    Determine length of unknown_fixed_prefix of a cipher that has an
    encryption API like this:

    AES_ECB(unknown_fixed_prefix || attacker_controlled || unknown_plaintext,
            unknown_key)

    Args:
        encrypt_func (function): Wrapper to victim's encryption API.
            encrypt_func takes one bytes argument, attacker_controlled,
            which will be injected to the unknown plaintext before it's
            encrypted.
            encrypt_func returns the resulting ciphertext.
    Returns:
        len(unknown_fixed_prefix) (int)
    """
    char = "B"
    num_continuous = 10
    i = 0
    user_input = (char * i).encode()
    ciphertext = encrypt_func(user_input)
    while (
        utils.max_num_identical_continuous_ciphertext_blocks(
            ciphertext, block_size=cipher_block_size
        )
        != num_continuous
    ):
        i += 1
        user_input = (char * i).encode()
        ciphertext = encrypt_func(user_input)
    block_size_bytes = cipher_block_size // 8
    b_chars_in_fixed_prefix_blocks = i - (num_continuous * block_size_bytes)

    i = 0
    while True:
        last_block = None
        found_num_continuous = True
        for j in range(i, i + num_continuous):
            block = utils.get_block(ciphertext, j, block_size=cipher_block_size)
            if last_block and last_block != block:
                found_num_continuous = False
                break
            last_block = block
        if found_num_continuous:
            break
        i += 1

    fixed_prefix_length = i * block_size_bytes - b_chars_in_fixed_prefix_blocks

    return fixed_prefix_length


def determine_cipher_block_size_by_prependable_plaintext(encrypt_func):
    """
    Determine block size of a cipher that has an encryption API like this:

    AES_ECB(attacker_controlled || unknown_plaintext, unknown_key)

    or this:

    AES_ECB(fixed_prefix || attacker_controlled || unknown_plaintext, unknown_key)

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
