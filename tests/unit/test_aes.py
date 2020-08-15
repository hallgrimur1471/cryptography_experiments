# pylint: disable=no-self-use, protected-access
import base64

import pytest

import drvn.cryptography.aes as aes


class TestEncryptEbc:
    def test_no_padding(self):
        plaintext = "STRAWBERRIES AND CHAMPAGNE :) :)".encode()
        key = "YELLOW_SUBMARINE".encode()

        cipher = aes.encrypt_ecb(plaintext, key, add_padding=False)

        assert (
            cipher
            == b"\xd1\x0c\x84=\xa3<\xb7\x1e\xe3\xa1\x91UN"
            + b"\x0c\x16\xf5>GE\x87<\xee\xf4\xedTd\xad\x00\xe9Q\xe8:"
        )

    def test_with_padding(self):
        plaintext = "STRAWBERRIES AND CHAMPAGNE :) :)".encode()
        key = "YELLOW_SUBMARINE".encode()

        cipher = aes.encrypt_ecb(plaintext, key, add_padding=True)

        assert (
            cipher
            == b"\xd1\x0c\x84=\xa3<\xb7\x1e\xe3\xa1\x91UN"
            + b"\x0c\x16\xf5>GE\x87<\xee\xf4\xedTd\xad\x00\xe9Q\xe8:"
            + b"\xad\xfd0\x11h\xb2&\xe2V\x14\xa1\x0f\x0bA\x0co"
        )


class TestDecryptEbc:
    def test_do_not_remove_padding(self):
        cipher = (
            b"\xd1\x0c\x84=\xa3<\xb7\x1e\xe3\xa1\x91UN"
            + b"\x0c\x16\xf5>GE\x87<\xee\xf4\xedTd\xad\x00\xe9Q\xe8:"
        )
        key = "YELLOW_SUBMARINE".encode()

        plaintext = aes.decrypt_ebc(cipher, key, remove_padding=False)

        assert plaintext == "STRAWBERRIES AND CHAMPAGNE :) :)".encode()

    def test_remove_padding(self):
        cipher = (
            b"\xd1\x0c\x84=\xa3<\xb7\x1e\xe3\xa1\x91UN"
            + b"\x0c\x16\xf5>GE\x87<\xee\xf4\xedTd\xad\x00\xe9Q\xe8:"
            + b"\xad\xfd0\x11h\xb2&\xe2V\x14\xa1\x0f\x0bA\x0co"
        )
        key = "YELLOW_SUBMARINE".encode()

        plaintext = aes.decrypt_ebc(cipher, key, remove_padding=True)

        assert plaintext == b"STRAWBERRIES AND CHAMPAGNE :) :)"


def test_encrypt_and_decrypt_ebc_returns_original_bytes():
    plaintext = "STRAWBERRIES AND CHAMPAGNE :) :)".encode()
    key = "YELLOW_SUBMARINE".encode()

    cipher = aes.encrypt_ecb(plaintext, key, add_padding=False)
    resulting_plaintext = aes.decrypt_ebc(cipher, key, remove_padding=False)

    assert plaintext == resulting_plaintext


class TestEncryptCbc:
    def test_add_padding(self):
        plaintext = (
            b"I'm back and I'm ringin' the bell \nA rockin' on "
            + b"the mike while the fly girls yel"
        )
        key = b"YELLOW SUBMARINE"
        iv = bytes([0] * 16)

        ciphertext = aes.encrypt_cbc(
            plaintext, key, iv, block_size=128, add_padding=True
        )

        assert (
            base64.b64encode(ciphertext)
            == b"CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DRF"
            + b"V/xIN2k8Go7jtArLIyP605b071DL8C+FPYSHOXPkMMMFP"
            + b"AKm+Nsu0nCBMQVt9mlltpwwry7hZr+sKfPn3Uzzs0"
        )

    def test_do_not_add_padding(self):
        plaintext = (
            b"I'm back and I'm ringin' the bell \nA rockin' on "
            + b"the mike while the fly girls yel"
        )
        key = b"YELLOW SUBMARINE"
        iv = bytes([0] * 16)

        ciphertext = aes.encrypt_cbc(
            plaintext, key, iv, block_size=128, add_padding=False
        )

        assert (
            base64.b64encode(ciphertext)
            == b"CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DR"
            + b"FV/xIN2k8Go7jtArLIyP605b071DL8C+FPYSHOXPkMMM"
            + b"FPAKm+Nsu0nCBMQVt9mlls="
        )


class TestDecryptCbc:
    def test_do_not_remove_padding(self):
        ciphertext = (
            b"\t\x120\xaa\xde>\xb30\xdb\xaaCX\xf8"
            + b"\x8d*l\xd5\xcf\x83U\xcbh#9z\xd49\x06\xdfCDU\x7f\xc4\x83v\x93"
            + b"\xc1\xa8\xee;@\xac\xb22?\xad9oN\xf5\x0c\xbf\x02\xf8S\xd8Hs"
            + b"\x97>C\x0c0S\xc0*o\x8d\xb2\xed'\x08\x13\x10V\xdff\x96["
        )
        key = b"YELLOW SUBMARINE"
        iv = bytes([0] * 16)

        plaintext = aes.decrypt_cbc(
            ciphertext, key, iv, block_size=128, remove_padding=False
        )

        assert (
            plaintext
            == b"I'm back and I'm ringin' the bell \nA rockin' on "
            + b"the mike while the fly girls yel"
        )

    def test_remove_padding(self):
        ciphertext = base64.b64decode(
            b"CRIwqt4+szDbqkNY+I0qbNXPg1XLaCM5etQ5Bt9DRF"
            + b"V/xIN2k8Go7jtArLIyP605b071DL8C+FPYSHOXPkMMMFP"
            + b"AKm+Nsu0nCBMQVt9mlltpwwry7hZr+sKfPn3Uzzs0"
        )
        key = b"YELLOW SUBMARINE"
        iv = bytes([0] * 16)

        plaintext = aes.decrypt_cbc(
            ciphertext, key, iv, block_size=128, remove_padding=True
        )

        assert (
            plaintext
            == b"I'm back and I'm ringin' the bell \nA rockin' on "
            + b"the mike while the fly girls yel"
        )


def test_encrypt_and_decrypt_cbc_returns_original_bytes():
    plaintext = "STRAWBERRIES AND CHAMPAGNE :) :)".encode()
    key = "YELLOW_SUBMARINE".encode()
    iv = bytes([0] * 16)

    ciphertext = aes.encrypt_cbc(plaintext, key, iv, add_padding=False)
    resulting_plaintext = aes.decrypt_cbc(
        ciphertext, key, iv, remove_padding=False
    )

    assert plaintext == resulting_plaintext


class TestDetectMode:
    def test_detects_ecb(self):
        ciphertext = bytes.fromhex(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd"
            + "283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f"
            + "4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af7"
            + "0dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af7"
            + "0dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b"
            + "29933f2c123c58386b06fba186a"
        )

        mode = aes.detect_mode(ciphertext)

        assert mode == "ecb"

    def test_detects_nothing(self):
        ciphertext = bytes.fromhex(
            "b563aac8275730bd4cf89ab32bb4b152be8fae16afab58ab3ea0e825c8ce28"
            + "ddbe26c8cafef763f1d9c3f30d60335cd0b765b98a11d5cfbe7a2d75e8f8a5e851"
            + "ee6a17de174d8bea5c1e089beffc99709d6dcc03e578220eccdfa99d3fa0a3d2f6736de"
            + "041cd783ad7f866df5dcd2a752cfbfc380cf84da5c5dd3fc486cf1adc14d29d9"
            + "e91737514e8c67d5c5aece4a19216e2b069f53b8ab4acaef17f815004"
        )

        mode = aes.detect_mode(ciphertext)

        assert mode != "ecb"


class TestFigureOutPrefixLength:
    def test_normal(self):
        unknown_fixed_prefix = "12345678901234567".encode()
        unknown_plaintext = "asdfasdf".encode()
        cipher_block_size = 128
        encrypt_func = self._create_victim_api(
            unknown_fixed_prefix, unknown_plaintext
        )

        length = aes.figure_out_prefix_length(encrypt_func, cipher_block_size)

        assert length == 17

    def test_prefix_contains_Bs(self):
        unknown_fixed_prefix = (
            "1234567890123456BBB".encode() + "BBBBBBBBBBBBBBBA".encode()
        )
        unknown_plaintext = "asdfasdf".encode()
        cipher_block_size = 128
        encrypt_func = self._create_victim_api(
            unknown_fixed_prefix, unknown_plaintext
        )

        length = aes.figure_out_prefix_length(encrypt_func, cipher_block_size)

        assert length == 19 + 16

    def test_prefix_ends_with_Bs(self):
        unknown_fixed_prefix = (
            "1234567890123456BBB".encode() + "BBBBBBBBBBBBBBBB".encode()
        )
        unknown_plaintext = "asdfasdf".encode()
        cipher_block_size = 128
        encrypt_func = self._create_victim_api(
            unknown_fixed_prefix, unknown_plaintext
        )

        length = aes.figure_out_prefix_length(encrypt_func, cipher_block_size)

        assert length == 19 + 16

    def _create_victim_api(self, unknown_fixed_prefix, unknown_plaintext):
        def encrypt_func(user_input):
            key = "MELLOW SUBMARINE".encode()
            plaintext_to_encrypt = (
                unknown_fixed_prefix + user_input + unknown_plaintext
            )
            ciphertext = aes.encrypt_ecb(plaintext_to_encrypt, key)
            return ciphertext

        return encrypt_func


class TestGenerateRandomAesKey:
    def test_returns_bytes(self):
        key = aes.generate_random_aes_key()

        assert isinstance(key, bytes)

    def test_is_16_bytes(self):
        key = aes.generate_random_aes_key()

        assert len(key) == 16

    def test_generates_different_keys(self):
        key_1 = aes.generate_random_aes_key()
        key_2 = aes.generate_random_aes_key()

        assert key_1 != key_2
