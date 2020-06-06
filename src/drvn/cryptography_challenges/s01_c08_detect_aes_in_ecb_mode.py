"""
Detect AES in ECB mode
"""
import logging
import os.path
import statistics
import collections

import drvn.cryptography_challenges._resources as resources


def run_challenge():
    logging.info("Running challenge 8 ...")

    ciphers = resources.get_contents("c08_detect_aes_in_ecb_mode.in")
    ciphers = ciphers.split("\n")
    ciphers = [line.rstrip() for line in ciphers]
    ciphers = list(filter(None, ciphers))
    for i, cipher in enumerate(ciphers):
        block_frequencies_tuples = calculate_block_frequencies(cipher)
        avg_freq = statistics.mean(
            [freq for block, freq in block_frequencies_tuples]
        )
        if avg_freq > 1:
            logging.info(
                "line {} might be encrypted with AES in ECB ".format(i + 1)
                + "because it contains reccurring 16 byte blocks "
                + "in the cipher."
            )


def get_script_directory():
    return os.path.dirname(os.path.abspath(__file__))


def calculate_block_frequencies(cipher):
    frequency_map = collections.defaultdict(int)
    block_size = 16
    i = 0

    while i + block_size <= len(cipher):
        block = cipher[i : i + block_size]
        frequency_map[block] += 1

        i += block_size

    block_frequencies_tuples = list(frequency_map.items())
    return block_frequencies_tuples
