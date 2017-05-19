from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.WinStructure import *
from lazagne.config.constant import *
import xml.etree.cElementTree as ET
import base64
import os

class RDPManager(ModuleInfo):
    def __init__(self):
        options = {'command': '--rdp', 'action': 'store_true', 'dest': 'rdp_manager', 'help': 'RDP Connection Manager'}
        ModuleInfo.__init__(self, 'rdpmanager', 'sysadmin', options)

    def decrypt_password(self, encrypted_password):
        try:
            decoded = base64.b64decode(encrypted_password)
            password_decryped = Win32CryptUnprotectData(decoded)
            password_decryped = password_decryped.replace('\x00', '')
        except:
            password_decryped = encrypted_password.replace('\x00', '')
        return password_decryped

    def format_output_tag(self, tag):
        tag = tag.lower()
        if 'username' in tag:
            tag = 'Login'
        elif 'hostname' in tag:
            tag = 'URL'
        return tag.capitalize()

    def check_tag_content(self, values, c):
        # values = {}
        if 'password' in c.tag.lower():
            values['Password'] = self.decrypt_password(c.text)
        else:
            tag = self.format_output_tag(c.tag)
            values[tag] = c.text
        return values

    def parse_element(self, root, element):
        pwdFound = []
        try:
            for r in root.findall(element):
                values = {}
                for child in r.getchildren():
                    if child.tag == 'properties':
                        for c in child.getchildren():
                            values = self.check_tag_content(values, c)
                    elif child.tag == 'logonCredentials':
                        for c in child.getchildren():
                            values = self.check_tag_content(values, c)
                    else:
                        values = self.check_tag_content(values, child)
                if values:
                    pwdFound.append(values)
        except Exception, e:
            print_debug('DEBUG', str(e))

        return pwdFound

    def parse_xml(self, setting):
        tree = ET.ElementTree(file=setting)
        root = tree.getroot()
        pwdFound = []

        elements = [
            'CredentialsProfiles/credentialsProfiles/credentialsProfile', 
            'DefaultGroupSettings/defaultSettings/logonCredentials',
            'file/server',
        ]

        for element in elements:
            pwdFound += self.parse_element(root, element)

        try:
            for r in root.find('FilesToOpen'):
                if os.path.exists(r.text):
                    print_debug('INFO', 'New setting file found: %s' % r.text)
                    pwdFound += self.parse_xml(r.text)
        except:
            pass

        return pwdFound

    def run(self, software_name = None):
        settings = [
            '%s\\Microsoft Corporation\\Remote Desktop Connection Manager\\RDCMan.settings' % constant.profile['LOCALAPPDATA'], 
            '%s\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings' % constant.profile['LOCALAPPDATA']
        ]

        for setting in settings:
            if os.path.exists(setting):
                print_debug('INFO', 'Setting file found: %s' % setting)
                return self.parse_xml(setting)
