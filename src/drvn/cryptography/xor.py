"""
XOR repeating-key encryption/decryption
"""

from math import floor
from statistics import mean

import drvn.cryptography.utils as utils


def encrypt(data, key):
    """
    Encrypt using repeating key XOR

    Args:
        data (bytes[array])
        key (bytes[array])
    Returns:
        cipher (bytes[array]) after applying repeating key xor encryption to
        data. In repeating key XOR, you'll sequentially XOR each byte of the
        key with each byte of data
    """
    cipher = bytearray(data)
    keysize = len(key)
    for i, byte in enumerate(cipher):
        cipher[i] = byte ^ key[i % keysize]
    return cipher


def decrypt(cipher):
    """
    Decrypt cipher that has been encrypted using repeating key XOR

    Args:
        cipher (bytes[array]): cipher to decrypt
    Returns:
        list of utils.DecryptionResult, the first element is the most likely data and
        key combination, the second element the second most likely etc...
    """
    print("determining key ...")
    # determine probable keysizes
    keysize_candidates = range(2, min(40, floor(len(cipher) / 2)))
    probable_keysizes = []  # [(keysize, hamming_distance), ...]
    for keysize in keysize_candidates:
        hamming_distances = []
        i = 0
        while (i + keysize) + keysize <= len(cipher):
            first = cipher[i : i + keysize]
            second = cipher[(i + keysize) : (i + keysize) + keysize]
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
        vertical = cipher[i::keysize]
        probable_char = single_byte_decryption(vertical)[0].key
        key.append(probable_char)
        print(key)

    # determine data
    cipher = bytes(cipher)
    key = bytes(key)
    data = encrypt(cipher, key)
    return utils.DecryptionResult(data, key)


def single_byte_decryption(cipher, num_results=1):
    """
    Args:
        cipher (bytes[array]): cipher to decrypt
        num_results (int): number of results to return
    Returns:
        list of utils.DecryptionResult, the first element is the most likely data, key
        combination according to english frequency analysis, the second element
        the second most likely etc...
        The list contains num_results elements.
    """
    key_candidates = bytes(range(0, 256))
    results = []
    for key in key_candidates:
        data = bytearray()
        for byte in cipher:
            data.append(byte ^ key)
        result = utils.DecryptionResult(data, key)
        results.append(result)
    results.sort(key=lambda m: m.frequency_distance)
    results_to_return = results[: min(num_results, len(results))]
    return results_to_return
