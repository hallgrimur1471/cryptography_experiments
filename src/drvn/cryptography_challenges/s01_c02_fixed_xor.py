"""
Fixed XOR test
"""

import logging
import binascii

import drvn.cryptography.utils as utils


def run_challenge():
    logging.info("Running challenge 2 ...")
    data1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    data2 = bytes.fromhex("686974207468652062756c6c277320657965")
    data_xor = utils.fixed_xor(data1, data2)
    logging.info(f"{data1} XOR {data2} = {data_xor}")
