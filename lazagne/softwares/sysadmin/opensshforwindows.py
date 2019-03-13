# -*- coding: utf-8 -*-
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant
# from Crypto.PublicKey import RSA
# from Crypto.PublicKey import DSA
import os


class OpenSSHForWindows(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'opensshforwindows', 'sysadmin')
        #self.key_files_location = os.path.join(constant.profile["USERPROFILE"], u'.ssh')

    # Retrieve SSH private key even if a passphrase is set (the goal is to remove crypto dependency)
    # def is_private_key_unprotected(self, key_content_encoded, key_algorithm):
    #     """
    #     Check if the private key can be loaded without specifying any passphrase.
    #
    #     PyCrypto >= 2.6.1 required in order to have the method importKey() in DSA class.
    #
    #     :param key_content_encoded: Encoded content of the private key to test
    #     :param key_algorithm: Algorithm of the key (RSA or DSA)
    #     :return: True only if the key can be successfuly loaded and is usable
    #     """
    #     state = False
    #     try:
    #         # Try to load it
    #         if key_algorithm == "RSA":
    #             key = RSA.importKey(key_content_encoded)
    #         else:
    #             key = DSA.importKey(key_content_encoded)
    #         # Validate loading
    #         state = (key is not None and key.can_sign() and key.has_private())
    #     except Exception as e:
    #         self.error(u"Cannot validate key protection '%s'" % e)
    #         state = False
    #         pass
    #
    #     return state

    def extract_private_keys_unprotected(self):
        """
        Extract all DSA/RSA private keys that are not protected with a passphrase.

        :return: List of encoded key (key file content)
        """
        keys = []
        if os.path.isdir(self.key_files_location):
            for (dirpath, dirnames, filenames) in os.walk(self.key_files_location, followlinks=True):
                for f in filenames:
                    key_file_path = os.path.join(dirpath, f)
                    if os.path.isfile(key_file_path):
                        try:
                            # Read encoded content of the key
                            with open(key_file_path, "r") as key_file:
                                key_content_encoded = key_file.read()
                            # Determine the type of the key (public/private) and what is it algorithm
                            if "DSA PRIVATE KEY" in key_content_encoded:
                                key_algorithm = "DSA"
                            elif "RSA PRIVATE KEY" in key_content_encoded or "OPENSSH PRIVATE KEY" in key_content_encoded:
                                key_algorithm = "RSA"
                            else:
                                key_algorithm = None
                            # Check if the key can be loaded (used) without passphrase
                            # if key_algorithm is not None and self.is_private_key_unprotected(key_content_encoded,
                            #                                                                    key_algorithm):
                            if key_algorithm:
                                keys.append(key_content_encoded)
                        except Exception as e:
                            self.error(u"Cannot load key file '%s' '%s'" % (key_file_path, e))
                            pass

        return keys

    def run(self):
        """
        Main function
        """
        self.key_files_location = os.path.join(constant.profile["USERPROFILE"], u'.ssh')
        # Extract all DSA/RSA private keys that are not protected with a passphrase
        unprotected_private_keys = self.extract_private_keys_unprotected()

        # Parse and process the list of keys
        key_found = []
        for key in unprotected_private_keys:
            values = {"Privatekey": key}
            key_found.append(values)

        return key_found
