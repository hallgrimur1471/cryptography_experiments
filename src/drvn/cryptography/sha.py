# pylint: disable=pointless-string-statement, wrong-import-position,no-self-use
"""
The code below is a modified version of this code:
https://github.com/ajalt/python-sha1/blob/master/sha1.py

Which has the MIT lience included in the next comment block:
"""

"""
The MIT License (MIT)

Copyright (c) 2013-2015 AJ Alt

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

import struct
import io


class Sha1Hash:
    """A class that mimics that hashlib api and implements the SHA-1 algorithm."""

    name = "python-sha1"
    digest_size = 20
    block_size = 64

    def __init__(self):
        # Initial digest variables
        self._h = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        )

        # bytes object with 0 <= len < 64 used to store the end of the message
        # if the message length is not congruent to 64
        self._unprocessed = b""
        # Length in bytes of all data that has been processed so far
        self._message_byte_length = 0

    def update(self, arg):
        """Update the current digest.
        This may be called repeatedly, even after calling digest or hexdigest.
        Arguments:
            arg: bytes, bytearray, or BytesIO object to read from.
        """
        if isinstance(arg, (bytes, bytearray)):
            arg = io.BytesIO(arg)

        # Try to build a chunk out of the unprocessed data, if any
        chunk = self._unprocessed + arg.read(64 - len(self._unprocessed))

        # Read the rest of the data, 64 bytes at a time
        while len(chunk) == 64:
            self._h = self._process_chunk(chunk, *self._h)
            self._message_byte_length += 64
            chunk = arg.read(64)

        self._unprocessed = chunk
        return self

    def digest(self):
        """Produce the final hash value (big-endian) as a bytes object"""
        # return b"".join(struct.pack(b">I", h) for h in self._produce_digest())
        h = self._produce_digest()
        return self._h_to_bytes(h)

    def hexdigest(self):
        """Produce the final hash value (big-endian) as a hex string"""
        return "%08x%08x%08x%08x%08x" % self._produce_digest()

    def _produce_digest(self):
        """Return finalized digest variables for the data processed so far."""
        # Pre-processing:
        message = self._unprocessed
        message_byte_length = self._message_byte_length + len(message)

        # append the bit '1' to the message
        message += b"\x80"

        # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
        # is congruent to 56 (mod 64)
        message += b"\x00" * ((56 - (message_byte_length + 1) % 64) % 64)

        # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
        message_bit_length = message_byte_length * 8
        message += struct.pack(b">Q", message_bit_length)

        # Process the final chunk
        # At this point, the length of the message is either 64 or 128 bytes.
        h = self._process_chunk(message[:64], *self._h)
        if len(message) == 64:
            return h

        h = self._process_chunk(message[64:], *h)
        return h

    def _left_rotate(self, n, b):
        """Left rotate a 32-bit integer n by b bits."""
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    # pylint:disable=too-many-locals
    def _process_chunk(self, chunk, h0, h1, h2, h3, h4):
        """Process a chunk of data and return the new digest variables."""
        assert len(chunk) == 64

        w = [0] * 80

        # Break chunk into sixteen 4-byte big-endian words w[i]
        for i in range(16):
            w[i] = struct.unpack(b">I", chunk[i * 4 : i * 4 + 4])[0]

        # Extend the sixteen 4-byte words into eighty 4-byte words
        for i in range(16, 80):
            w[i] = self._left_rotate(
                w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1
            )

        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in range(80):
            if 0 <= i <= 19:
                # Use alternative 1 for f from FIPS PB 180-1 to avoid bitwise not
                f = d ^ (b & (c ^ d))
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = (
                (self._left_rotate(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF,
                a,
                self._left_rotate(b, 30),
                c,
                d,
            )

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

        return h0, h1, h2, h3, h4

    def _h_to_bytes(self, h):
        return b"".join(struct.pack(b">I", x) for x in h)


def sha1(data):
    """SHA-1 Hashing Function
    A custom SHA-1 hashing function implemented entirely in Python.
    Arguments:
        data: A bytes or BytesIO object containing the input message to hash.
    Returns:
        A SHA-1 digest of the input message.
    """
    return Sha1Hash().update(data).digest()


"""
###############################################################################
##################################### NOTE ####################################
###############################################################################
The code below is NOT a part of
https://github.com/ajalt/python-sha1/blob/master/sha1.py
so the MIT licence above does not apply the code here below
"""


# pylint:disable=too-many-locals
def sha1_length_extension_attack(
    authenticated_data, authenticated_data_mac, suffix_to_forge, is_valid
):
    """
    Args:
        authenticated_data (bytes)
        authenticated_data_mac (bytes):
            = SHA1(secret_key + authenticated_data)
        suffix_to_forge(bytes)
        is_valid (func):
            is_valid(forged_data, forged_mac) should call Victim's API to check
            if (forged_data, forged_mac) are valid
    Returns:
        SHA1(secret_key + authenticated_data + glue_padding + suffix_to_forge)
    given
    """
    auth_mac = authenticated_data_mac

    secret_key_length = 0  # This needs to be guessed
    secret_key_length = len(b"very secret key")  # TODO: remove
    while True:
        message_length = secret_key_length + len(authenticated_data)
        glue_padding = calculate_glue_padding(message_length)

        (a, b, c, d, e) = (
            int.from_bytes(auth_mac[0:4], "big"),
            int.from_bytes(auth_mac[4:8], "big"),
            int.from_bytes(auth_mac[8:12], "big"),
            int.from_bytes(auth_mac[12:16], "big"),
            int.from_bytes(auth_mac[16:20], "big"),
        )
        s = Sha1Hash()

        # Configure internal state of Sha1 to be the same
        # as when it finished processing the authenticated data.
        # pylint:disable=protected-access
        s._h = (a, b, c, d, e)
        s._message_byte_length = message_length + len(glue_padding)

        s.update(suffix_to_forge)
        forged_mac = s.digest()

        forged_data = authenticated_data + glue_padding + suffix_to_forge
        if is_valid(forged_data, forged_mac):
            return forged_data, forged_mac

        secret_key_length += 1

        raise RuntimeError("Boom!")


def calculate_glue_padding(msg_len):
    """
    The code in this function is based on the MIT licenced code above
    """
    padding = b"\x80"
    padding += b"\x00" * ((56 - (msg_len + 1) % 64) % 64)
    padding += struct.pack(b">Q", msg_len * 8)
    return padding
