# -*- coding: utf-8 -*-
import hashlib
import struct
from Crypto.Cipher import AES
from pureSalsa20 import Salsa20

AES_BLOCK_SIZE = 16

def sha256(s):
    """Return SHA256 digest of the string `s`."""
    return hashlib.sha256(s).digest()

def transform_key(key, seed, rounds):
    """Transform `key` with `seed` `rounds` times using AES ECB."""
    # create transform cipher with transform seed
    cipher = AES.new(seed, AES.MODE_ECB)
    # transform composite key rounds times
    for n in range(0, rounds):
        key = cipher.encrypt(key)
    # return hash of transformed key
    return sha256(key)

def aes_cbc_decrypt(data, key, enc_iv):
    """Decrypt and return `data` with AES CBC."""
    cipher = AES.new(key, AES.MODE_CBC, enc_iv)
    return cipher.decrypt(data)

def aes_cbc_encrypt(data, key, enc_iv):
    cipher = AES.new(key, AES.MODE_CBC, enc_iv)
    return cipher.encrypt(data)

def unpad(data):
    extra = ord(data[-1])
    return data[:len(data)-extra]

def pad(s):
    n = AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE
    return s + n * struct.pack('b', n)

def xor(aa, bb):
    """Return a bytearray of a bytewise XOR of `aa` and `bb`."""
    result = bytearray()
    for a, b in zip(bytearray(aa), bytearray(bb)):
        result.append(a ^ b)
    return result
