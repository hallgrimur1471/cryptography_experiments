#!/usr/bin/env python3

from cryptography_experiments import xor
from cryptography_experiments.utils import DecryptionResult

plaintext = ("I'm still a student.."
             "I have a lot of things to do."
             "This plan requires secrecy, Slip on your shoes."
             "This text needs to be longer for the english character frequency "
             "to work better. Now I am just writing something, hopefully this"
             "will work if i just keep typing, because I really hope there"
             "is not a bug in my code. In that case I would be writing for"
             "no reasons and the computers would laugh at me. I am a little bit"
             "surprised now that the decryption is not working still, well now"
             "something is happening... the code guessed honoluluhonolulu"
             "it's extremely stupid to think that's the code when you know we"
             "are dealing with repeating key xor encryption... "
             "Let's hope I don't break the frequency analysis now but: "
             "Sá hlær best sem síðast hlær. Yeah .... I broke it now it thought"
             "the password was honolulu7honolulu, but let's hope after writing "
             "this it has been fixed. Yeah it's back to thinking the key is"
             "honoluluhonolulu ..LOL".encode())
print(" **** plaintext ****")
print(plaintext.decode())
key = "honolulu".encode()
print(" **** key ****")
print(key.decode())

cipher = xor.encrypt(plaintext, key) #  repeating key xor encryption
print(" *** cipher ***")
print(cipher)

print("\n ******** BREAKING REPEATING KEY XOR ********")
decryptionResult = xor.decrypt(cipher)
print(" *** most probable key ***\n"+decryptionResult.key.decode())
print(" *** most probable data ***\n"+decryptionResult.data.decode())
