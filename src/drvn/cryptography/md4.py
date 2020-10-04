# pylint:disable=invalid-name,pointless-string-statement
"""
The code below is a modified version of this code:
https://gist.github.com/BenWiederhake/eb6dfc2c31d3dc8c34508f4fd091cea9
"""

import logging
import struct
import copy


def md4(msg):
    md = MD4()
    md.add(msg)
    mac = md.finish()
    return mac


class MD4:
    def __init__(self, data=b""):
        self.remainder = data
        self.count = 0
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def _add_chunk(self, chunk):
        self.count += 1
        X = list(struct.unpack("<16I", chunk) + (None,) * (80 - 16))
        h = copy.copy(self.h)
        # Round 1
        s = (3, 7, 11, 19)
        for r in range(16):
            i = (16 - r) % 4
            k = r
            h[i] = leftrotate(
                (
                    h[i]
                    + F(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4])
                    + X[k]
                )
                % 2 ** 32,
                s[r % 4],
            )
        # Round 2
        s = (3, 5, 9, 13)
        for r in range(16):
            i = (16 - r) % 4
            k = 4 * (r % 4) + r // 4
            h[i] = leftrotate(
                (
                    h[i]
                    + G(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4])
                    + X[k]
                    + 0x5A827999
                )
                % 2 ** 32,
                s[r % 4],
            )
        # Round 3
        s = (3, 9, 11, 15)
        k = (
            0,
            8,
            4,
            12,
            2,
            10,
            6,
            14,
            1,
            9,
            5,
            13,
            3,
            11,
            7,
            15,
        )
        for r in range(16):
            i = (16 - r) % 4
            h[i] = leftrotate(
                (
                    h[i]
                    + H(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4])
                    + X[k[r]]
                    + 0x6ED9EBA1
                )
                % 2 ** 32,
                s[r % 4],
            )

        for i, v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2 ** 32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = b""
        for chunk in range(0, len(message) - r, 64):
            self._add_chunk(message[chunk : chunk + 64])
        return self

    def finish(self):
        l = len(self.remainder) + 64 * self.count
        self.add(b"\x80" + b"\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8))
        out = struct.pack("<4I", *self.h)
        self.__init__()
        return out


def F(x, y, z):
    return (x & y) | (~x & z)


def G(x, y, z):
    return (x & y) | (x & z) | (y & z)


def H(x, y, z):
    return x ^ y ^ z


def leftrotate(i, n):
    return ((i << n) & 0xFFFFFFFF) | (i >> (32 - n))


"""
###############################################################################
##################################### NOTE ####################################
###############################################################################
The code below is NOT a part of
https://gist.github.com/BenWiederhake/eb6dfc2c31d3dc8c34508f4fd091cea9
"""


# pylint:disable=too-many-locals
def md4_length_extension_attack(
    authenticated_data, authenticated_data_mac, suffix_to_forge, is_valid
):
    """
    Args:
        authenticated_data (bytes)
        authenticated_data_mac (bytes):
            = MD4(secret_key + authenticated_data)
        suffix_to_forge(bytes)
        is_valid (func):
            is_valid(forged_data, forged_mac) should call Victim's API to check
            if (forged_data, forged_mac) are valid
    Returns:
        MD4(secret_key + authenticated_data + glue_padding + suffix_to_forge)
    given
    """
    auth_mac = authenticated_data_mac

    secret_key_length = 0  # This needs to be guessed
    while True:
        logging.debug(
            f"Trying length extension attack with {secret_key_length=} ..."
        )
        message_length = secret_key_length + len(authenticated_data)
        glue_padding = calculate_glue_padding(message_length)

        (a, b, c, d) = (
            int.from_bytes(auth_mac[0:4], "little"),
            int.from_bytes(auth_mac[4:8], "little"),
            int.from_bytes(auth_mac[8:12], "little"),
            int.from_bytes(auth_mac[12:16], "little"),
        )
        md = MD4()

        # Configure internal state of MD4 to be the same
        # as when it finished processing the authenticated data.
        md.h = [a, b, c, d]
        assert (message_length + len(glue_padding)) % 64 == 0
        md.count = (message_length + len(glue_padding)) // 64

        md.add(suffix_to_forge)
        forged_mac = md.finish()

        forged_data = authenticated_data + glue_padding + suffix_to_forge
        if is_valid(forged_data, forged_mac):
            return forged_data, forged_mac

        secret_key_length += 1


def calculate_glue_padding(msg_len):
    return (
        b"\x80"
        + b"\x00" * ((55 - msg_len) % 64)
        + struct.pack("<Q", msg_len * 8)
    )
