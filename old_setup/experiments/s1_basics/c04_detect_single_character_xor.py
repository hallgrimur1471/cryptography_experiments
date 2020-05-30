#!/usr/bin/env python3

"""
Finds line in file that has been encrypted using single-character XOR
"""

from os.path import join, dirname, realpath

from cryptolib import xor

def main():
    root_folder = dirname(realpath(__file__))
    with open(join(root_folder, "c04_detect_single_character_xor.in")) as f:
        data = list(map(lambda line: line.rstrip(), f.readlines()))
        data = list(map(lambda line: bytes.fromhex(line), data))

    decrypted_lines = []
    for i, line in enumerate(data):
        print("Analysing line {}/{}".format(i+1, len(data)))
        decrypted = xor.single_byte_decryption(line)
        decrypted = decrypted[0]
        decrypted_lines.append(decrypted)
    decrypted_lines.sort(key=lambda m: m.frequency_distance)
    most_probable = decrypted_lines[0]
    print("data: ", most_probable.data)
    print("key: ", chr(most_probable.key))

if __name__ == "__main__":
    main()
