import time


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

        return y & ((2 ** w) - 1)

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


def crack_unix_timestamp_seed(
    outputs, approximate_time=None, timeout=10, mt19937_bits=32
):
    current_unix_timestamp = int(time.time())
    start_time = current_unix_timestamp
    if approximate_time == None:
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
