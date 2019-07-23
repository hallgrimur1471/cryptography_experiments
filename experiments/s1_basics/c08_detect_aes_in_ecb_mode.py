#!/usr/bin/env python3

from os.path import dirname, join, realpath

from Crypto.Cipher import AES
from Crypto import Random

# read cipher from file
with open(join(dirname(realpath(__file__)), "c08_detect_aes_in_ecb_mode.in")) \
        as f:
    cipher = list(map(lambda line: line.rstrip(), f.readlines()))
    cipher = list(map(lambda line: bytes.fromhex(line), cipher))

for line in cipher:
    i = 0
    while i < len(cipher):
        j = 1
        #print("i: ", i)
        while i + (j+1)*16 <= len(cipher):
            #print("j: ", j)
            if cipher[i:i+16] == cipher[i + j*16:i + (j+1)*16]:
                print("duplicate")
            j += 1
        i += 1
print("done")

#key = b'YELLOW SUBMARINE'
#iv = Random.new().read(AES.block_size)
#aes = AES.new(key, AES.MODE_ECB, iv)
#
#msg = "blackbird is litblackbird is lit"
#
#cipher = aes.encrypt(msg)
#print(cipher[0:16])
#print(cipher[16:32])
#
#data = aes.decrypt(cipher)
#print(data)
