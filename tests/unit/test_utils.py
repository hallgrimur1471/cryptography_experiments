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

    def test_plaintext_bytes_are_modulo_zero_to_block_size(self):
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


class TestIsValidPadding:
    def test_normal(self):
        assert utils.is_valid_pkcs7_padding(b"YELLOW SUBMARIN\x01")
        assert utils.is_valid_pkcs7_padding(b"YELLOW SUBMARI\x02\x02")
        assert utils.is_valid_pkcs7_padding(b"YELLOW SUBMAR\x03\x03\x03")
        assert utils.is_valid_pkcs7_padding(b"YELLOW SUBMA\x04\x04\x04\x04")
        assert utils.is_valid_pkcs7_padding(b"YELLOW SUBM\x05\x05\x05\x05\x05")

    def test_refuses_no_padding(self):
        assert not utils.is_valid_pkcs7_padding(b"YELLOW SUBMARINE")

    def test_accepts_full_block_padding(self):
        assert utils.is_valid_pkcs7_padding(
            b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        )

    def test_refuses_too_long_padding(self):
        assert not utils.is_valid_pkcs7_padding(
            b"\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11"
        )

    def test_zero_byte_is_not_valid_padding(self):
        assert not utils.is_valid_pkcs7_padding(b"YELLOW SUBMARIN\x00")


class TestMaxNumIdenticalContinuousCiphertextBlocks:
    def test_normal(self):
        ciphertext = (
            bytes.fromhex("fbddc8f375e1d967ca17358b98382d7c")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
            + bytes.fromhex("f0b24d856e59d62b41b0b371834d793a")
        )

        n = utils.max_num_identical_continuous_ciphertext_blocks(ciphertext)

        assert n == 4

    def test_non_continuous(self):
        ciphertext = (
            bytes.fromhex("fbddc8f375e1d967ca17358b98382d7c")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
            + bytes.fromhex("f0b24d856e59d62b41b0b371834d793a")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
            + bytes.fromhex("44cd65fd1ccf70b3229e44dc02284459")
        )

        n = utils.max_num_identical_continuous_ciphertext_blocks(ciphertext)

        assert n == 3


class TestFindValueWithResults:
    def test_normal(self):
        v = 42
        f = lambda v: v ** 2 + v
        results = 1806

        v_deduced = utils.find_value_with_results(f, results)

        assert v_deduced == v


class TestReverseOperations1:
    def test_normal(self):
        x, rshift, magic, results = (123456, 5, 0xCAFEBABE, 125010)

        x_deduced = utils.reverse_operations_1(rshift, magic, results)

        assert x_deduced == x


class TestReverseOperations2:
    def test_normal(self):
        x, lshift, magic, results = (7890, 4, 0xBABECAFE, 55026)

        x_deduced = utils.reverse_operations_2(lshift, magic, results)

        assert x_deduced == x

    def test_normal_for_debug(self):
        x, lshift, magic, results = (
            int("1101", 2),
            int("0001", 2),
            int("1010", 2),
            int("0111", 2),
        )

        x_deduced = utils.reverse_operations_2(lshift, magic, results)

        assert x_deduced == x


class TestGetBit:
    def test_normal(self):
        x = 6

        assert utils.get_bit(0, x) == 0
        assert utils.get_bit(1, x) == 1
        assert utils.get_bit(2, x) == 1
        assert utils.get_bit(3, x) == 0
        assert utils.get_bit(4, x) == 0


class TestSetBit:
    def test_normal(self):
        x = int("101001", 2)

        assert utils.set_bit(2, 0, x) == int("101001", 2)
        assert utils.set_bit(2, 1, x) == int("101101", 2)

        x = int("111001", 2)
        assert utils.set_bit(4, 0, x) == int("101001", 2)
        assert utils.set_bit(4, 1, x) == int("111001", 2)
