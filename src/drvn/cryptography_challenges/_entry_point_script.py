import logging
import argparse

import drvn.cryptography._logging as drvn_logger
import drvn.cryptography_challenges.challenges as challenges


def main():
    args = _parse_arguments()

    if args.verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    drvn_logger.configure(log_level)

    challenges.run(args.CHALLENGE)


def _parse_arguments():
    parser = argparse.ArgumentParser()
    parser.description = "Runs a cryptopals.com challenge."
    parser.add_argument("CHALLENGE", type=int, help="Challenge number")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enables printing of debug statements",
    )
    arguments = parser.parse_args()
    return arguments
