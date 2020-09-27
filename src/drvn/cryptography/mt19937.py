import time

import drvn.cryptography.utils as utils


class MT19937:
    def __init__(self, bits=32):
        if bits == 32:
            (w, n, m, r) = (32, 624, 397, 31)
            a = 0x9908B0DF
            (u, d) = (11, 0xFFFFFFFF)
            (s, b) = (7, 0x9D2C5680)
            (t, c) = (15, 0xEFC60000)
            l = 18
            f = 1812433253
        elif bits == 64:
            (w, n, m, r) = (64, 312, 156, 31)
            a = 0xB5026F5AA96619E9
            (u, d) = (29, 0x5555555555555555)
            (s, b) = (17, 0x71D67FFFEDA60000)
            (t, c) = (37, 0xFFF7EEE000000000)
            l = 43
            f = 6364136223846793005
        else:
            raise ValueError("bits must be 32 or 64")

        (
            self.w,
            self.n,
            self.m,
            self.r,
            self.a,
            self.u,
            self.d,
            self.s,
            self.b,
            self.t,
            self.c,
            self.l,
            self.f,
        ) = (w, n, m, r, a, u, d, s, b, t, c, l, f)

        self.mt = [0] * n
        self.index = None
        self.lower_mask = int("1" * r, 2)
        self.upper_mask = int("1" * (w - r) + "0" * r, 2)

        self.seed(5489)

    def get_number(self):
        (w, n, u, d, s, b, t, c, l, mt) = (
            self.w,
            self.n,
            self.u,
            self.d,
            self.s,
            self.b,
            self.t,
            self.c,
            self.l,
            self.mt,
        )

        if self.index == n:
            self._twist()

        y = mt[self.index]
        y ^= (y >> u) & d
        y ^= (y << s) & b
        y ^= (y << t) & c
        y ^= y >> l

        self.index += 1
        num = y & ((2 ** w) - 1)

        return num

    def seed(self, seed: int):
        (w, n, f, mt) = (self.w, self.n, self.f, self.mt)
        self.index = n
        mt[0] = seed
        for i in range(1, n):
            mt[i] = (f * (mt[i - 1] ^ (mt[i - 1] >> (w - 2))) + i) & (
                (2 ** w) - 1
            )

    def _twist(self):
        (n, m, a, mt) = (
            self.n,
            self.m,
            self.a,
            self.mt,
        )

        for i in range(n):
            x = self.mt[i] & self.upper_mask
            xA = x >> 1
            if (x % 2) != 0:
                xA = xA ^ a
            mt[i] = mt[(i + m) % n] ^ xA
        self.index = 0


def clone_rng(nums, bits=32):
    if bits != 32:
        raise ValueError("This function only supports cloning a 32 bit MT19937")

    if len(nums) < 624:
        raise ValueError("'nums' must contain at least 625 numbers")

    clone = _clone_rng_from_624_numbers(nums[0:624])

    # The MT19937 has now successfully been cloned but it needs to be tapped
    # len(nums) - 624 times to arrive to the same number as the original RNG
    i = 624
    while i < len(nums):
        clone.get_number()
        i += 1

    return clone


# pylint: disable=too-many-locals
def _clone_rng_from_624_numbers(nums):
    """
    Args:
        nums ([int]):
            list of 624 integers, the required amount to deduce MT19937's state
    """
    mt = MT19937()
    n, u, d, s, b, t, c, l = (
        624,
        11,
        0xFFFFFFFF,
        7,
        0x9D2C5680,
        15,
        0xEFC60000,
        18,
    )
    for i in range(0, 624):
        num = nums[i]

        # w = 32
        # num == y1 & ((2 ** w) - 1)
        # => last w bits of y1 are same as the bits of num
        #
        # we do not need to worry about the higer order bits than w
        # so we can use num as y1
        y1 = num

        # Now these MT19937 calculations will be reversed:
        # y = mt[self.index]
        # y ^= (y >> u) & d
        # y ^= (y << s) & b
        # y ^= (y << t) & c
        # y ^= y >> l

        # y1 = y2 ^ (y2 >> l)
        # y1 = y2 ^ ((y2 >> l) & 0xFFFFFFFF)
        y2 = utils.reverse_operations_1(l, 0xFFFFFFFF, y1)

        # y2 = y3 ^ ((y3 << t) & c)
        y3 = utils.reverse_operations_2(t, c, y2)

        # y3 = y4 ^ ((y4 << s) & b)
        y4 = utils.reverse_operations_2(s, b, y3)

        # y4 = y5 ^ ((y5 >> u) & d)
        y5 = utils.reverse_operations_1(u, d, y4)

        reversed_mt_value = y5

        mt.mt[i] = reversed_mt_value

    mt.index = n

    return mt


class Keystream:
    def __init__(self, seed=None):
        self.mt = MT19937()
        if seed:
            self.mt.seed(seed)

        self.bytes = bytearray()

    def get_byte(self):
        if not self.bytes:
            num = self.mt.get_number()
            bytes_ = num.to_bytes(4, byteorder="little")
            self.bytes = bytearray(bytes_)

        byte = self.bytes.pop()
        return byte


def stream_cipher_encrypt(plaintext, key):
    keystream = Keystream(key)
    ciphertext = bytearray()
    for byte in plaintext:
        ciphertext.append(byte ^ keystream.get_byte())
    return bytes(ciphertext)


def stream_cipher_decrypt(ciphertext, key):
    return stream_cipher_encrypt(ciphertext, key)


def crack_unix_timestamp_seed(
    outputs, approximate_time=None, timeout=10, mt19937_bits=32
):
    current_unix_timestamp = int(time.time())
    start_time = current_unix_timestamp
    if approximate_time is None:
        approximate_time = current_unix_timestamp

    mt = MT19937(bits=mt19937_bits)

    i = 0
    mt.seed(approximate_time + i)
    resulting_outputs = [mt.get_number() for _ in range(len(outputs))]
    while True:
        if time.time() - start_time >= timeout:
            raise RuntimeError("Cracking unix timestamp seed timed out")

        for cracked_seed in [approximate_time + i, approximate_time - i]:
            mt.seed(cracked_seed)
            resulting_outputs = [mt.get_number() for _ in range(len(outputs))]
            if resulting_outputs == outputs:
                return cracked_seed

        i += 1
