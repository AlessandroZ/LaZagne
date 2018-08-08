# -*- coding: utf-8 -*- 
import array
import base64
import binascii
import hashlib
import os
import re
from xml.etree.cElementTree import ElementTree

from lazagne.config.constant import constant
from lazagne.config.crypto.pyDes import des, CBC
from lazagne.config.module_info import ModuleInfo


class Dbvisualizer(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, name='dbvis', category='databases')

        self._salt = self.get_salt()
        self._passphrase = 'qinda'
        self._iteration = 10

    def get_salt(self):
        salt_array = [-114, 18, 57, -100, 7, 114, 111, 90]
        salt = array.array('b', salt_array)
        hexsalt = binascii.hexlify(salt)
        return binascii.unhexlify(hexsalt)

    def get_derived_key(self, password, salt, count):
        key = bytearray(password) + salt

        for i in range(count):
            m = hashlib.md5(key)
            key = m.digest()
        return key[:8], key[8:]

    def decrypt(self, msg):
        enc_text = base64.b64decode(msg)
        (dk, iv) = self.get_derived_key(self._passphrase, self._salt, self._iteration)
        crypter = des(dk, CBC, iv)
        text = crypter.decrypt(enc_text)
        return re.sub(r'[\x01-\x08]', '', text)

    def run(self):
        path = os.path.join(constant.profile['HOMEPATH'], u'.dbvis', u'config70', u'dbvis.xml')
        if os.path.exists(path):
            tree = ElementTree(file=path)

            pwd_found = []
            elements = {'Alias': 'Name', 'Userid': 'Login', 'Password': 'Password', 'UrlVariables//Driver': 'Driver'}

            for e in tree.findall('Databases/Database'):
                values = {}
                for elem in elements:
                    try:
                        if elem != "Password":
                            values[elements[elem]] = e.find(elem).text
                        else:
                            values[elements[elem]] = self.decrypt(e.find(elem).text)
                    except Exception:
                        pass

                try:
                    elem = e.find('UrlVariables')
                    for ee in elem.getchildren():
                        for ele in ee.getchildren():
                            if 'Server' == ele.attrib['UrlVariableName']:
                                values['Host'] = str(ele.text)
                            if 'Port' == ele.attrib['UrlVariableName']:
                                values['Port'] = str(ele.text)
                            if 'SID' == ele.attrib['UrlVariableName']:
                                values['SID'] = str(ele.text)
                except Exception:
                    pass

                if values:
                    pwd_found.append(values)

            return pwd_found
