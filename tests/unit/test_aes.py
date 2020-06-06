# pylint: disable=no-self-use, protected-access

import drvn.cryptography.aes as aes


class TestEncryptEbc:
    def test_normal(self):
        plaintext = "STRAWBERRIES AND CHAMPAGNE :) :)".encode()
        key = "YELLOW_SUBMARINE".encode()

        cipher = aes.encrypt_ebc(plaintext, key)

        assert (
            cipher
            == b"\xd1\x0c\x84=\xa3<\xb7\x1e\xe3\xa1\x91UN"
            + b"\x0c\x16\xf5>GE\x87<\xee\xf4\xedTd\xad\x00\xe9Q\xe8:"
        )


class TestDecryptEbc:
    def test_normal(self):
        cipher = (
            b"\xd1\x0c\x84=\xa3<\xb7\x1e\xe3\xa1\x91UN"
            + b"\x0c\x16\xf5>GE\x87<\xee\xf4\xedTd\xad\x00\xe9Q\xe8:"
        )
        key = "YELLOW_SUBMARINE".encode()

        plaintext = aes.decrypt_ebc(cipher, key)

        assert plaintext == "STRAWBERRIES AND CHAMPAGNE :) :)".encode()


def test_encrypt_and_decrypt_ebc_returns_original_bytes():
    plaintext = "STRAWBERRIES AND CHAMPAGNE :) :)".encode()
    key = "YELLOW_SUBMARINE".encode()

    cipher = aes.encrypt_ebc(plaintext, key)
    resulting_plaintext = aes.decrypt_ebc(cipher, key)

    assert plaintext == resulting_plaintext


class TestEncryptCbc:
    def test_normal(self):
        plaintext = (
            b"I'm back and I'm ringin' the bell \nA rockin' on "
            + b"the mike while the fly girls yel"
        )
        key = b"YELLOW SUBMARINE"
        iv = bytes([0] * 16)

        ciphertext = aes.encrypt_cbc(plaintext, key, iv, block_size=16)

        assert ciphertext == (
            b"\t\x120\xaa\xde>\xb30\xdb\xaaCX\xf8"
            + b"\x8d*l\xd5\xcf\x83U\xcbh#9z\xd49\x06\xdfCDU\x7f\xc4\x83v\x93"
            + b"\xc1\xa8\xee;@\xac\xb22?\xad9oN\xf5\x0c\xbf\x02\xf8S\xd8Hs"
            + b"\x97>C\x0c0S\xc0*o\x8d\xb2\xed'\x08\x13\x10V\xdff\x96["
        )


class TestDecryptCbc:
    def test_normal(self):
        ciphertext = (
            b"\t\x120\xaa\xde>\xb30\xdb\xaaCX\xf8"
            + b"\x8d*l\xd5\xcf\x83U\xcbh#9z\xd49\x06\xdfCDU\x7f\xc4\x83v\x93"
            + b"\xc1\xa8\xee;@\xac\xb22?\xad9oN\xf5\x0c\xbf\x02\xf8S\xd8Hs"
            + b"\x97>C\x0c0S\xc0*o\x8d\xb2\xed'\x08\x13\x10V\xdff\x96["
        )
        print(len(ciphertext))
        key = b"YELLOW SUBMARINE"
        iv = bytes([0] * 16)

        plaintext = aes.decrypt_cbc(ciphertext, key, iv, block_size=16)

        assert (
            plaintext
            == b"I'm back and I'm ringin' the bell \nA rockin' on "
            + b"the mike while the fly girls yel"
        )


def test_encrypt_and_decrypt_cbc_returns_original_bytes():
    plaintext = "STRAWBERRIES AND CHAMPAGNE :) :)".encode()
    key = "YELLOW_SUBMARINE".encode()
    iv = bytes([0] * 16)

    ciphertext = aes.encrypt_cbc(plaintext, key, iv)
    resulting_plaintext = aes.decrypt_cbc(ciphertext, key, iv)

    assert plaintext == resulting_plaintext
