"""
XOR repeating-key encryption/decryption
"""

from math import floor
from statistics import mean

import drvn.cryptography.utils as utils


def encrypt(plaintext, key):
    """
    Encrypt using repeating key XOR

    Args:
        plaintext (bytes[array])
        key (bytes[array])
    Returns:
        ciphertext (bytes[array]) after applying repeating key xor encryption to
        plaintext. In repeating key XOR, you'll sequentially XOR each byte of the
        key with each byte of plaintext
    """
    ciphertext = bytearray(plaintext)
    keysize = len(key)
    for i, byte in enumerate(ciphertext):
        ciphertext[i] = byte ^ key[i % keysize]
    return ciphertext


def decrypt(ciphertext):
    """
    Decrypt ciphertext that has been encrypted using repeating key XOR

    Args:
        ciphertext (bytes[array]): ciphertext to decrypt
    Returns:
        list of utils.DecryptionResult, the first element is the most likely plaintext and
        key combination, the second element the second most likely etc...
    """
    print("determining key ...")
    # determine probable keysizes
    keysize_candidates = range(2, min(40, floor(len(ciphertext) / 2)))
    probable_keysizes = []  # [(keysize, hamming_distance), ...]
    for keysize in keysize_candidates:
        hamming_distances = []
        i = 0
        while (i + keysize) + keysize <= len(ciphertext):
            first = ciphertext[i : i + keysize]
            second = ciphertext[(i + keysize) : (i + keysize) + keysize]
            hamming_distances.append(utils.hamming_distance(first, second))
            i += 2 * keysize
        normalized_hamming_distance = mean(hamming_distances) / keysize
        probable_keysizes.append((keysize, normalized_hamming_distance))
    probable_keysizes.sort(key=lambda x: x[1])
    print("keysize {} most probable".format(probable_keysizes[0][0]))

    # determine key
    key = bytearray()
    keysize = probable_keysizes[0][0]
    for i in range(0, keysize):
        vertical = ciphertext[i::keysize]
        probable_char = single_byte_decryption(vertical)[0].key
        key.append(probable_char)
        print(key)

    # determine plaintext
    ciphertext = bytes(ciphertext)
    key = bytes(key)
    plaintext = encrypt(ciphertext, key)
    return utils.DecryptionResult(plaintext, key)


def single_byte_decryption(ciphertext, num_results=1):
    """
    Args:
        ciphertext (bytes[array]): ciphertext to decrypt
        num_results (int): number of results to return
    Returns:
        list of utils.DecryptionResult, the first element is the most likely plaintext, key
        combination according to english frequency analysis, the second element
        the second most likely etc...
        The list contains num_results elements.
    """
    key_candidates = bytes(range(0, 256))
    results = []
    for key in key_candidates:
        plaintext = bytearray()
        for byte in ciphertext:
            plaintext.append(byte ^ key)
        result = utils.DecryptionResult(plaintext, key)
        results.append(result)
    results.sort(key=lambda m: m.frequency_distance)
    results_to_return = results[: min(num_results, len(results))]
    return results_to_return
