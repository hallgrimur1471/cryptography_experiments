"""
Crack an MT19937 seed
"""

import logging
import time
import random

import drvn.cryptography.mt19937 as mt19937


def run_challenge():
    mt = mt19937.MT19937()

    logging.info("Waiting a bit ...")
    time.sleep(random.randint(5, 15))

    current_unix_timestamp = int(time.time())
    logging.info(
        f"Seeding MT19937 with current unix timestamp ({current_unix_timestamp}) ..."
    )
    mt.seed(current_unix_timestamp)

    logging.info("Waiting a bit ...")
    time.sleep(random.randint(5, 15))

    logging.info("Querying MT19937 for a number ...")
    first_output = mt.get_number()
    logging.info(f"First output of the MT19937 is {first_output}")

    logging.info("Cracking the MT19937 seed ...")
    seed = mt19937.crack_unix_timestamp_seed(
        [first_output], approximate_time=int(time.time()), timeout=5
    )
    logging.info(f"The generator's seed is '{seed}'")
