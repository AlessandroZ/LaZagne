# -*- coding: utf-8 -*-
import base64
import fnmatch
import os
import rsa
import string

from random import *
from xml.dom import minidom

try:
    import _winreg as winreg
except ImportError:
    import winreg


from lazagne.config.module_info import ModuleInfo


class IISCentralCertP(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, name='iiscentralcertp', category='sysadmin', registry_used=True, winapi_used=True)

    def find_files(self, path, file):
        """
        Try to find all files with the same name
        """
        founded_files = []
        for dirpath, dirnames, files in os.walk(path):
            for file_name in files:
                if fnmatch.fnmatch(file_name, file):
                    founded_files.append(dirpath + '\\' + file_name)

        return founded_files

    def create_RSAKeyValueFile(self, exe_file, container):
        tmp_file = "".join(choice(string.ascii_letters + string.digits) for x in range(randint(8, 10))) + ".xml"
        try:
            os.system(exe_file + " -px " + container + " " + tmp_file + " -pri > nul")
        except OSError:
            self.debug(u'Error executing {container}'.format(container=container))
            tmp_file = ''

        return tmp_file

    def get_registry_key(self, reg_key, parameter):
        data = ''
        try:
            if reg_key.startswith('HKEY_LOCAL_MACHINE'):
                hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key.replace('HKEY_LOCAL_MACHINE\\', ''))
            data = winreg.QueryValueEx(hkey, parameter)[0]
        
        except Exception as e:
            self.debug(e)

        return data

    def decrypt_hash_b64(self, hash_b64, privkey):
        hash = bytearray(base64.b64decode(hash_b64))
        hash.reverse()
        hash_b64 = base64.b64encode(hash)
        hash = base64.b64decode(hash_b64)
        message = rsa.decrypt(hash, privkey)
        return message.decode('UTF-16')

    def GetLong(self, nodelist):
        rc = []
        for node in nodelist:
            if node.nodeType == node.TEXT_NODE:
                rc.append(node.data)

        st = ''.join(rc)
        raw = base64.b64decode(st)
        return int(raw.encode('hex'), 16)

    def read_RSAKeyValue(self, rsa_key_xml):
        xmlStructure = minidom.parseString(rsa_key_xml)

        MODULUS = self.GetLong(xmlStructure.getElementsByTagName('Modulus')[0].childNodes)
        EXPONENT = self.GetLong(xmlStructure.getElementsByTagName('Exponent')[0].childNodes)
        D = self.GetLong(xmlStructure.getElementsByTagName('D')[0].childNodes)
        P = self.GetLong(xmlStructure.getElementsByTagName('P')[0].childNodes)
        Q = self.GetLong(xmlStructure.getElementsByTagName('Q')[0].childNodes)
        InverseQ = self.GetLong(xmlStructure.getElementsByTagName('InverseQ')[0].childNodes)

        privkey = rsa.PrivateKey(MODULUS, EXPONENT, D, P, Q)
        self.debug(u'RSA Key Value - PEM:\n {RSAkey}'.format(RSAkey=privkey.save_pkcs1(format='PEM')))

        return privkey

    def run(self):
        pfound = []

        ccp_enabled = self.get_registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IIS\\CentralCertProvider',
                                            'Enabled')
        if ccp_enabled != 1:
            self.debug(u'IIS CentralCertProvider is not enabled')
            return

        exe_files = self.find_files(os.environ['WINDIR'] + '\\Microsoft.NET\\Framework64\\', 'aspnet_regiis.exe')
        if len(exe_files) == 0:
            exe_files = self.find_files(os.environ['WINDIR'] + '\\Microsoft.NET\\Framework\\', 'aspnet_regiis.exe')
            if len(exe_files) == 0:
                self.debug(u'File not found aspnet_regiis.exe')
                return

        self.info(u'aspnet_regiis.exe files found: {files}'.format(files=exe_files))
        rsa_xml_file = self.create_RSAKeyValueFile(exe_files[-1], "iisWASKey")
        if rsa_xml_file == '':
            self.debug(u'Problems extracting RSA Key Value')
            return

        with open(rsa_xml_file, 'rb') as File:
            rsa_key_xml = File.read()

        os.remove(rsa_xml_file)
        self.debug(u'Temporary file removed: {filename}'.format(filename=rsa_xml_file))
        privkey = self.read_RSAKeyValue(rsa_key_xml)
        values = {}
        
        CertStoreLocation = self.get_registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IIS\\CentralCertProvider',
                                                  'CertStoreLocation')
        values['CertStoreLocation'] = CertStoreLocation
        
        username = self.get_registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IIS\\CentralCertProvider',
                                         'Username')
        values['Username'] = username
        
        pass64 = self.get_registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IIS\\CentralCertProvider',
                                       'Password')
        values['Password'] = self.decrypt_hash_b64(pass64, privkey)

        privpass64 = self.get_registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\IIS\\CentralCertProvider',
                                           'PrivateKeyPassword')
        values['Private Key Password'] = self.decrypt_hash_b64(privpass64, privkey)

        pfound.append(values)
        return pfound 
