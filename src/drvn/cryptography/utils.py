"""
Various utility functions
"""

import subprocess
import base64

import drvn.cryptography._resources as resources


class DecryptionResult:
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
        self._freq_dist = None  # frequency distance
        self._english_char_freq = None  # english character frequencies

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
        data = self._data  # copy() not requred since bytes in not mute-able
        for char, engish_freq in self._english_char_freq.items():
            # todo: move normalize_caps to a place where it can be modified
            normalize_caps = False
            if normalize_caps:
                data = bytearray(data)  # slow!
                for i, byte in enumerate(data):
                    if chr(byte).isalpha():
                        data[i] = ord(chr(byte).lower())
            occurs_num = len([byte for byte in data if byte == ord(char)])
            frequency = float(occurs_num) / len(data)
            char_score = abs(frequency - engish_freq)
            char_scores.append(char_score)
        freq_dist = sum(char_scores)
        return freq_dist

    # pylint: disable=no-self-use
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
        f = resources.get_contents("character_frequency_in_english.txt")
        for line in filter(None, f.split("\n")):
            line = line.split()
            char = line[0]
            freq = line[1]
            char_freq[char] = int(freq)
        total_chars = sum(char_freq.values())
        for k, v in char_freq.items():
            char_freq[k] = float(v) / total_chars
        return char_freq

    def __repr__(self):
        return f"DecryptionResult(data={self.data}, key={self.key})"


def hamming_distance(a, b):
    """
    The hamming distance is just the number of differing bits

    Args:
        a (bytes[array])
        b (bytes[array])
    Returns:
        hamming distance (int) between a and b
    """
    return sum([1 for bit in bytes_to_bin(fixed_xor(a, b)) if bit == "1"])


def fixed_xor(a, b):
    """
    a XOR b

    Args:
        a (bytes[array])
        b (bytes[array])
    Returns:
        a XOR b (bytes[array])
    """
    return bytes([i ^ j for i, j in zip(a, b)])


def hex_string_to_base64_string(hex_string):
    bytes_ = bytes.fromhex(hex_string)
    encoded_bytes = base64.b64encode(bytes_)
    base64_string = encoded_bytes.decode()
    return base64_string


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
    num = int.from_bytes(b, byteorder="big")
    return bin(num)[2:]


def add_pkcs7_padding(bytes_, block_size=8):
    """
    Add padding to bytes_

    Examples:
        b'YELLOW_SUBMARINE', block_size=10 -> b'YELLOW_SUBMARINE\x04\x04\x04\x04'
    """
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in the range [1, 255]")

    num_missing = block_size - (len(bytes_) % block_size)
    padding = bytes([num_missing] * num_missing)
    bytes_padded = bytes_ + padding
    return bytes_padded


def try_cmd(*args, **kwargs):
    kwargs["check"] = True

    try:
        completed_process = cmd(*args, **kwargs)
    except subprocess.CalledProcessError as e:
        msg = f"Command '{e.cmd}' returned non-zero exit status {e.returncode}."
        if e.stdout or e.stderr:
            msg += "\n"
        if e.stdout:
            msg += f"\nHere is its stdout:\n{e.stdout.decode()}"
        if e.stderr:
            msg += f"\nHere is its stderr:\n{e.stderr.decode()}"
        raise RuntimeError(msg)

    return completed_process


def cmd(*args, **kwargs):
    if "shell" not in kwargs:
        kwargs["shell"] = True
    if "executable" not in kwargs:
        kwargs["executable"] = "/bin/bash"

    # pylint: disable=subprocess-run-check
    completed_process = subprocess.run(*args, **kwargs)
    return completed_process
