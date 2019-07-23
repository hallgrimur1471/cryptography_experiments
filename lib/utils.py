#!/usr/bin/env python3

"""
Various utility functions
"""

import sys
import os
import os.path
from os.path import dirname
#from statistics import mean
import base64
#import inspect

class DecryptionResult(object):
    """
    Stores results of a decryption, calculates it's likeness to english.
    """

    def __init__(self, data, key):
        """
        Args:
            data (bytes)
            key (bytes)
        """
        self._data = data
        self._key = key
        self._freq_dist = None # frequency distance
        self._english_char_freq = None # english character frequencies

    @property
    def data(self):
        return self._data

    @property
    def key(self):
        return self._key

    @property
    def frequency_distance(self):
        if self._freq_dist is None:
            self._freq_dist = self._calculate_freq_dist()
        return self._freq_dist

    def _calculate_freq_dist(self):
        """
        Returns:
            freq_dist (float). A score specifying likeness of self.data
            and typical english sentences. The lower the value of freq_dist
            the more similar self.data is to english.
        """
        if self._english_char_freq is None:
            self._english_char_freq = self._calculate_english_char_freq()
        # the lower the frequency_distance, the better
        char_scores = []
        data = self._data # copy() not requred since bytes in not mute-able
        for char, engish_freq in self._english_char_freq.items():
            # todo: move normalize_caps to a place where it can be modified
            normalize_caps = False
            if normalize_caps:
                data = bytearray(data) # slow!
                for i, byte in enumerate(data):
                    if chr(byte).isalpha():
                        data[i] = ord(chr(byte).lower())
            occurs_num = len([byte for byte in data if byte == ord(char)])
            frequency = float(occurs_num)/len(data)
            char_score = abs(frequency - engish_freq)
            char_scores.append(char_score)
        freq_dist = sum(char_scores)
        return freq_dist

    def _calculate_english_char_freq(self):
        """
        Returns:
            char_freq (dict). Dictionary where:
                key: english character
                value: percentage specifying how common the character is
                       in english.
        """
        # make a lookup table with info about english character frequency
        char_freq = dict()
        matasano_directory = dirname(sys.path[0])
        with open(os.path.join(matasano_directory,
                               "character_frequency_in_english.txt")) as f:
            for line in f:
                line = line.split()
                char = line[0]
                freq = line[1]
                char_freq[char] = int(freq)
        total_chars = sum(char_freq.values())
        for k, v in char_freq.items():
            char_freq[k] = float(v)/total_chars
        return char_freq

def hamming_distance(a, b):
    """
    The hamming distance is just the number of differing bits

    Args:
        a (bytes[array])
        b (bytes[array])
    Returns:
        hamming distance (int) between a and b
    """
    return sum([1 for bit in bytes_to_bin(fixed_xor(a, b)) if bit=='1'])

def fixed_xor(a, b):
    """
    a XOR b

    Args:
        a (bytes[array])
        b (bytes[array])
    Returns:
        a XOR b (bytes[array])
    """
    return bytes([i^j for i, j in zip(a, b)])

def hex_to_base64(hex_):
    """
    Args:
        hex_ (bytes[array])
    Returns:
        base64_ (bytes[array]). base64 representation of hex
    """
    base64_ = base64.b64encode(hex_)
    return base64_

def hex_string_to_int(hex_string):
    """
    Args:
        hex_string (string)
    Returns:
        int. The int that the hex_string represented.
    Examples:
        'ff'  -> 255
        '0xff -> 255
    """
    return int(hex_string, 16)

def bytes_to_bin(b):
    """
    Converts bytes to binary string

    Args:
        b (bytes[array])
    Returns:
        string. binary representation of b
    Examples:
        b'\x05' -> '101'
        b'\xff\x00' -> '1111111100000000'
    """
    num = int.from_bytes(b, byteorder='big')
    return bin(num)[2:]

# hex string to bytes:
#   bytes.fromhex('deadbeef')
