# pylint:disable=unnecessary-lambda
"""
Finds line in file that has been encrypted using single-character XOR
"""
import logging

import drvn.cryptography.xor as xor
import drvn.cryptography_challenges._resources as resources


def run_challenge():
    logging.info("Running challenge 4 ...")

    data = resources.get_contents("c04_detect_single_character_xor.in")
    data = [line.rstrip() for line in data.split("\n")]
    data = [bytes.fromhex(line) for line in data]

    decrypted_lines = []
    for i, line in enumerate(data):
        logging.info("Analysing line {}/{}".format(i + 1, len(data)))
        decrypted = xor.single_byte_decryption(line)
        decrypted = decrypted[0]
        decrypted_lines.append(decrypted)
    decrypted_lines.sort(key=lambda m: m.frequency_distance)
    most_probable = decrypted_lines[0]
    logging.info(f"data: {most_probable.data}")
    logging.info(f"key: {chr(most_probable.key)}")
