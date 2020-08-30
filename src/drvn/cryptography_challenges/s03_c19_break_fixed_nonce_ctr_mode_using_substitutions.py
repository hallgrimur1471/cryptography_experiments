"""
Break fixed-nonce CTR mode using substitutions
"""

import base64
import logging

import drvn.cryptography.aes as aes


def run_challenge():
    victim_api = VictimAPI()
    ciphertexts = victim_api.get_ciphertexts()
    plaintexts = aes.decrypt_ctr_ciphertexts_with_fixed_nonce(ciphertexts)

    for ciphertext, plaintext in zip(ciphertexts, plaintexts):
        logging.info(
            f"\nThe ciphertext:\n{ciphertext}\nwas decrypted to:\n{plaintext}\n"
        )

    msg = ""
    for ciphertext in ciphertexts:
        msg += f"{ciphertext.hex()}\n"
    logging.info(f"ciphertexts:\n{msg}")

    msg = ""
    for plaintext in plaintexts:
        msg += f"{str(bytes(plaintext))}\n"
    logging.info(f"plaintexts:\n{msg}")


# pylint: disable=no-self-use
class VictimAPI:
    def __init__(self):
        self._nonce = 0
        self._key = aes.generate_random_aes_key()

        self._ciphertexts = None

    def get_ciphertexts(self):
        if not self._ciphertexts:
            self._produce_ciphertexts()
        return self._ciphertexts

    def _produce_ciphertexts(self):
        plaintexts = self._get_plaintexts()
        self._ciphertexts = [
            aes.encrypt_ctr(txt, self._key, self._nonce) for txt in plaintexts
        ]

    def _get_plaintexts(self):
        return [
            base64.b64decode(txt)
            for txt in [
                "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
                "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
                "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
                "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
                "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
                "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
                "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
                "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
                "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
                "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
                "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
                "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
                "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
                "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
                "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
                "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
                "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
                "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
                "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
                "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
                "U2hlIHJvZGUgdG8gaGFycmllcnM/",
                "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
                "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
                "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
                "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
                "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
                "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
                "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
                "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
                "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
                "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
                "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
                "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
                "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
                "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
                "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
                "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
                "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
            ]
        ]
