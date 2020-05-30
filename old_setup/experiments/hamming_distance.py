#!/usr/bin/env python3

from cryptolib.utils import hamming_distance

assert hamming_distance(b'\x01', b'\x01') == 0
assert hamming_distance(b'\x00', b'\x01') == 1
assert hamming_distance(b'\x0f', b'\x05') == 2

a = bytes("this is a test", "utf-8")
b = bytes("wokka wokka!!!", "utf-8")
assert hamming_distance(a, b) == 37

print('Success')
