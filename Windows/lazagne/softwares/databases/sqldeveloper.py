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


class SQLDeveloper(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'sqldeveloper', 'databases')

        self._salt = self.get_salt()
        self._passphrase = None
        self._iteration = 42

    def get_salt(self):
        salt_array = [5, 19, -103, 66, -109, 114, -24, -83]
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

    def get_passphrase(self, path):
        xml_name = u'product-preferences.xml'
        xml_file = None

        if os.path.exists(os.path.join(path, xml_name)):
            xml_file = os.path.join(path, xml_name)
        else:
            for p in os.listdir(path):
                if p.startswith('system'):
                    new_directory = os.path.join(path, p)

                    for pp in os.listdir(new_directory):
                        if pp.startswith(u'o.sqldeveloper'):
                            if os.path.exists(os.path.join(new_directory, pp, xml_name)):
                                xml_file = os.path.join(new_directory, pp, xml_name)
                            break
        if xml_file:
            tree = ElementTree(file=xml_file)
            for elem in tree.iter():
                if 'n' in elem.attrib.keys():
                    if elem.attrib['n'] == 'db.system.id':
                        return elem.attrib['v']

    def run(self):
        path = os.path.join(constant.profile['APPDATA'], u'SQL Developer')
        if os.path.exists(path):
            self._passphrase = self.get_passphrase(path)
            if self._passphrase:
                self.debug(u'Passphrase found: {passphrase}'.format(passphrase=self._passphrase))
                xml_name = u'connections.xml'
                xml_file = None

                if os.path.exists(os.path.join(path, xml_name)):
                    xml_file = os.path.join(path, xml_name)
                else:
                    for p in os.listdir(path):
                        if p.startswith('system'):
                            new_directory = os.path.join(path, p)

                            for pp in os.listdir(new_directory):
                                if pp.startswith(u'o.jdeveloper.db.connection'):
                                    if os.path.exists(os.path.join(new_directory, pp, xml_name)):
                                        xml_file = os.path.join(new_directory, pp, xml_name)
                                    break

                if xml_file:
                    renamed_value = {'sid': 'SID', 'port': 'Port', 'hostname': 'Host', 'user': 'Login',
                                     'password': 'Password', 'ConnName': 'Name', 'customUrl': 'URL',
                                     'SavePassword': 'SavePassword', 'driver': 'Driver'}
                    tree = ElementTree(file=xml_file)

                    pwd_found = []
                    for e in tree.findall('Reference'):
                        values = {}
                        for ee in e.findall('RefAddresses/StringRefAddr'):
                            if ee.attrib['addrType'] in renamed_value and ee.find('Contents').text is not None:
                                name = renamed_value[ee.attrib['addrType']]
                                value = ee.find('Contents').text if name != 'Password' else self.decrypt(
                                    ee.find('Contents').text)
                                values[name] = value

                        pwd_found.append(values)

                    return pwd_found
