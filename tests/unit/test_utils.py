# pylint: disable=no-self-use, protected-access

import pytest

import drvn.cryptography.utils as utils


class TestHexStringToBase64String:
    def test_normal(self):
        hex_string = (
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120"
            "706f69736f6e6f7573206d757368726f6f6d"
        )

        results = utils.hex_string_to_base64_string(hex_string)

        expected_base64_string = (
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )
        assert results == expected_base64_string


class TestFixedXor:
    def test_normal(self):
        data1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
        data2 = bytes.fromhex("686974207468652062756c6c277320657965")

        data_xor = utils.fixed_xor(data1, data2)

        assert data_xor == bytes.fromhex("746865206b696420646f6e277420706c6179")


class TestHammingDistance:
    def test_normal(self):
        assert utils.hamming_distance(b"\x00", b"\x01") == 1
        assert utils.hamming_distance(b"\x0f", b"\x05") == 2

    def test_zero(self):
        assert utils.hamming_distance(b"\x00", b"\x00") == 0

    def test_cryptopals_example(self):
        a = bytes("this is a test", "utf-8")
        b = bytes("wokka wokka!!!", "utf-8")

        distance = utils.hamming_distance(a, b)

        assert distance == 37


class TestAddPkcs7Padding:
    def test_block_size_larger_than_bytes(self):
        plaintext = "YELLOW SUBMARINE".encode()

        padded_plaintext = utils.add_pkcs7_padding(plaintext, block_size=20)

        assert padded_plaintext == b"YELLOW SUBMARINE\x04\x04\x04\x04"

    def test_block_size_less_than_bytes(self):
        plaintext = "YELLOW SUBMARINE".encode()

        padded_plaintext = utils.add_pkcs7_padding(plaintext, block_size=5)

        assert padded_plaintext == b"YELLOW SUBMARINE\x04\x04\x04\x04"

    def test_bytes_are_modulo_zero_to_block_size(self):
        plaintext = "YELLOW SUBMARINE".encode()

        padded_plaintext = utils.add_pkcs7_padding(plaintext, block_size=8)

        assert (
            padded_plaintext
            == b"YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08"
        )

    def test_block_size_must_be_larger_than_zero(self):
        plaintext = "YELLOW SUBMARINE".encode()

        with pytest.raises(ValueError):
            utils.add_pkcs7_padding(plaintext, block_size=0)

    def test_block_size_must_be_less_than_256(self):
        plaintext = "YELLOW SUBMARINE".encode()

        with pytest.raises(ValueError):
            utils.add_pkcs7_padding(plaintext, block_size=256)


class TestRemovePkcs7Padding:
    def test_normal(self):
        plaintext_padded = b"YELLOW SUBMARINE\x04\x04\x04\x04"

        plaintext = utils.remove_pkcs7_padding(plaintext_padded)

        assert plaintext == b"YELLOW SUBMARINE"

    def test_invalid(self):
        plaintext_padded = b"YELLOW SUBMARINE\x05\x04\x04\x04"

        with pytest.raises(ValueError):
            utils.remove_pkcs7_padding(plaintext_padded)
