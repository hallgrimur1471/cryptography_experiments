#!/usr/bin/env python3

import os.path
import statistics
import collections


def main():
    ciphers = read_ciphers_from_input_file()
    for i, cipher in enumerate(ciphers):
        block_frequencies_tuples = calculate_block_frequencies(cipher)
        avg_freq = statistics.mean(
            [freq for block, freq in block_frequencies_tuples]
        )
        if avg_freq > 1:
            # print(block_frequencies_tuples)
            # print(i + 1, avg_freq)
            print(
                "line {} might be encrypted with AES in ECB ".format(i + 1)
                + "because it contains reccurring 16 byte blocks "
                + "in the cipher."
            )


def read_ciphers_from_input_file():
    script_directory = get_script_directory()
    input_file = os.path.join(script_directory, "c08_detect_aes_in_ecb_mode.in")

    with open(input_file, "r") as f:
        ciphers = f.readlines()

    ciphers = [cipher.rstrip() for cipher in ciphers]

    return ciphers


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


if __name__ == "__main__":
    main()

# read cipher from file
# with open(
#    join(dirname(realpath(__file__)), "c08_detect_aes_in_ecb_mode.in")
# ) as f:
#    cipher = list(map(lambda line: line.rstrip(), f.readlines()))
#    cipher = list(map(lambda line: bytes.fromhex(line), cipher))
#
# for line in cipher:
#    i = 0
#    while i < len(cipher):
#        j = 1
#        # print("i: ", i)
#        while i + (j + 1) * 16 <= len(cipher):
#            # print("j: ", j)
#            if cipher[i : i + 16] == cipher[i + j * 16 : i + (j + 1) * 16]:
#                print("duplicate")
#            j += 1
#        i += 1
# print("done")

# key = b'YELLOW SUBMARINE'
# iv = Random.new().read(AES.block_size)
# aes = AES.new(key, AES.MODE_ECB, iv)
#
# msg = "blackbird is litblackbird is lit"
#
# cipher = aes.encrypt(msg)
# print(cipher[0:16])
# print(cipher[16:32])
#
# data = aes.decrypt(cipher)
# print(data)
