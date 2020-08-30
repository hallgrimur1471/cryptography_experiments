"""
Implement the MT19937 Mersenne Twister RNG
"""

import logging

import drvn.cryptography.mt19937 as mt19937

# pylint: disable=invalid-name
def run_challenge():
    for bits in [32, 64]:
        mt = mt19937.MT19937(bits=bits)
        N = 10
        nums = [mt.get_number() for _ in range(N)]
        logging.info(
            f"\n{N} Random numbers from the {bits}-bit MT19937 generator:\n{nums}"
        )
