#!/usr/bin/env python


"""
    https://raw.githubusercontent.com/bozhu/RC4-Python/master/rc4.py

    Copyright (C) 2012 Bo Zhu http://about.bozhu.me

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation
    the rights to use, copy, modify, merge, publish, distribute, sublicense,
    and/or sell copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
    THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.
"""
class RC4:
    def __init__(self, key):
        self.key  = key
        self.S    = self.KSA()
        self.keystream = self.PRGA()

    def KSA(self):
        keylength = len(self.key)

        S = list(range(256))

        j = 0
        for i in range(256):
            j = (j + S[i] + self.key[i % keylength]) % 256
            S[i], S[j] = S[j], S[i]  # swap

        return S

    def PRGA(self):
        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + self.S[i]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]  # swap

            K = self.S[(self.S[i] + self.S[j]) % 256]
            yield K


    def encrypt(self, data):
        res = b''
        for b in data:
            res += (b ^ next(self.keystream)).to_bytes(1, byteorder = 'big', signed = False)
        return res

    def decrypt(self, data):
        return self.encrypt(data)