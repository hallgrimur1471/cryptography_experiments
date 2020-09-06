"""
Clone an MT19937 RNG from its output
"""

import random
import logging

import drvn.cryptography.mt19937 as mt19937


def run_challenge():
    mt = mt19937.MT19937()

    # Tap random number of times so we don't know generator's index variable
    logging.info(
        "Tapping original MT19937 a few times "
        + "so we don't know it's index variable ..."
    )
    for _ in range(random.randint(0, 624)):
        mt.get_number()

    logging.info(
        "Tapping the original MT19937 for 624 values "
        + "and using them to clone the MT19937 ..."
    )
    nums = [mt.get_number() for _ in range(624)]
    mt_cloned = mt19937.clone_rng(nums)

    predicted_next_num = mt_cloned.get_number()
    logging.info(
        f"Cloned twister predicts next number will be {predicted_next_num}"
    )

    next_num = mt.get_number()
    logging.info(f"Next number from original twister was {next_num}")

    logging.info(
        "Using cloned MT19937 to predict next 10 numbers:\n"
        + f"{[mt_cloned.get_number() for _ in range(10)]}"
    )
    logging.info(
        "Next 10 numbers from original twister:\n"
        + f"{[mt.get_number() for _ in range(10)]}"
    )

    # assert next_num == predicted_next_num
