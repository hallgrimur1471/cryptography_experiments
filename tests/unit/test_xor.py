# pylint: disable=no-self-use, protected-access

# import pytest

import drvn.cryptography.xor as xor


class TestSingleByteDecryption:
    def test_normal(self):
        cipher = bytes.fromhex(
            "1b37373331363f78151b7f2b783431333d78397828372d363c7"
            "8373e783a393b3736"
        )

        r = xor.single_byte_decryption(cipher, num_results=1)[0]

        assert r.data == b"Cooking MC's like a pound of bacon"
        assert r.key == 88


class TestEncrypt:
    def test_normal(self):
        data = (
            b"Burning 'em, if you ain't quick and nimble\n"
            + b"I go crazy when I hear a cymbal"
        )
        key = b"ICE"

        cipher = xor.encrypt(data, key)

        assert cipher == bytes.fromhex(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63"
            "343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b202763"
            "0c692b20283165286326302e27282f"
        )
