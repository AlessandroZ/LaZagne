# -*- coding: utf-8 -*-
import hashlib
import struct

from lazagne.config.crypto.pyaes.aes import AESModeOfOperationECB, AESModeOfOperationCBC
from lazagne.config.winstructure import char_to_int

AES_BLOCK_SIZE = 16


def sha256(s):
    """Return SHA256 digest of the string `s`."""
    return hashlib.sha256(s).digest()


def transform_key(key, seed, rounds):
    """Transform `key` with `seed` `rounds` times using AES ECB."""
    # create transform cipher with transform seed
    cipher = AESModeOfOperationECB(seed)
    # transform composite key rounds times
    for n in range(0, rounds):
        key = b"".join([cipher.encrypt(key[i:i + AES_BLOCK_SIZE]) for i in range(0, len(key), AES_BLOCK_SIZE)])
    # return hash of transformed key
    return sha256(key)


def aes_cbc_decrypt(data, key, enc_iv):
    """Decrypt and return `data` with AES CBC."""
    cipher = AESModeOfOperationCBC(key, iv=enc_iv)
    return b"".join([cipher.decrypt(data[i:i + AES_BLOCK_SIZE]) for i in range(0, len(data), AES_BLOCK_SIZE)])


def aes_cbc_encrypt(data, key, enc_iv):
    cipher = AESModeOfOperationCBC(key, iv=enc_iv)
    return b"".join([cipher.encrypt(data[i:i + AES_BLOCK_SIZE]) for i in range(0, len(data), AES_BLOCK_SIZE)])


def unpad(data):
    extra = char_to_int(data[-1])
    return data[:len(data) - extra]


def pad(s):
    n = AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE
    return s + n * struct.pack('b', n)


def xor(aa, bb):
    """Return a bytearray of a bytewise XOR of `aa` and `bb`."""
    result = bytearray()
    for a, b in zip(bytearray(aa), bytearray(bb)):
        result.append(a ^ b)
    return result
