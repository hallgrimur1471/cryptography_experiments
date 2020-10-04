# pylint: disable=no-self-use, protected-access, invalid-name

import drvn.cryptography.sha as sha


class TestCalculateGluePadding:
    def test_normal(self):
        msg = b"authenticated data\n"

        glue_padding = sha.calculate_glue_padding(len(msg))

        assert (
            glue_padding
            == b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x98"
        )

    def test_longer_than_64_bytes(self):
        msg = b"A" * 64 + b"B"

        glue_padding = sha.calculate_glue_padding(len(msg))

        assert (
            glue_padding
            == b"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            + b"\x00\x00\x00\x00\x00\x00\x02\x08"
        )
