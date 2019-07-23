#!/usr/bin/env python3

"""
todo: write docstring for module
"""

import sys
from os.path import abspath

# matsano crypto modules
matsano_crypto_challenges = abspath("../")
sys.path.insert(1, matsano_crypto_challenges)
import utils as ut # pylint: disable=wrong-import-position

def main():
    pass

if __name__ == "__main__":
    main()
