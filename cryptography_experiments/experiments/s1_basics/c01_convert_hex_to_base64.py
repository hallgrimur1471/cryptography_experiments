#!/usr/bin/env python3

"""
Convert hex to base64 test
"""

from cryptography_experiments import utils

def main():
    hex_string = ("49276d206b696c6c696e6720796f757220627261696e206c696b65206120"
                  "706f69736f6e6f7573206d757368726f6f6d")
    hex_bytes = bytes.fromhex(hex_string)
    base64_bytes = utils.hex_to_base64(hex_bytes)
    print(base64_bytes.decode())
    assert base64_bytes.decode() == ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgc"
                                     "G9pc29ub3VzIG11c2hyb29t")

if __name__ == "__main__":
    main()
