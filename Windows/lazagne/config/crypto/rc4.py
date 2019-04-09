# Thanks to g2jun for his RC4-Python project
# Code from https://github.com/g2jun/RC4-Python

from lazagne.config.winstructure import char_to_int, chr_or_byte


class RC4(object):

    def __init__(self, key):
        self.key_bytes = self.text_to_bytes(key)

    def text_to_bytes(self, text):
        byte_list = []

        # on Windows, default coding for Chinese is GBK
        # s = s.decode('gbk').encode('utf-8')
        for byte in text:
            byte_list.append(char_to_int(byte))

        return byte_list

    def bytes_to_text(self, byte_list):
        s = b''
        for byte in byte_list:
            s += chr_or_byte(byte)
        return s

    def encrypt(self, data):
        plain_bytes = self.text_to_bytes(data)
        keystream_bytes, cipher_bytes = self.crypt(plain_bytes, self.key_bytes)
        return self.bytes_to_text(cipher_bytes)

    def crypt(self, plain_bytes, key_bytes):

        keystream_list = []
        cipher_list = []

        key_len = len(key_bytes)
        plain_len = len(plain_bytes)
        S = list(range(256))

        j = 0
        for i in range(256):
            j = (j + S[i] + key_bytes[i % key_len]) % 256
            S[i], S[j] = S[j], S[i]

        i = 0
        j = 0
        for m in range(plain_len):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            keystream_list.append(k)
            cipher_list.append(k ^ plain_bytes[m])

        return keystream_list, cipher_list