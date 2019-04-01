# -*- coding: utf-8 -*-
try: 
    import _winreg as winreg
except ImportError:
    import winreg

from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import OpenKey, HKEY_LOCAL_MACHINE
from lazagne.config.constant import constant
from lazagne.config.users import get_username_winapi


class WindowsPassword(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'windows', 'windows')
        self.current_user = get_username_winapi()

    def is_in_domain(self):
        """
        Return the context of the host
        If a domain controller is set we are in an active directory.
        """
        try:
            key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\')
            val, _ = winreg.QueryValueEx(key, 'DCName')
            winreg.CloseKey(key)
            return val
        except Exception:
            return False

    def run(self):
        """
        - Check if the user password has already be found using Pypykatz
        - If not, check if a password stored in another application is also used as windows password
        - Windows password not found, return the DPAPI hash (not admin priv needed) to bruteforce using John or Hashcat
        """
        # Check if password has already been found
        if constant.pypykatz_result.get(self.current_user, None):
            if 'Password' in constant.pypykatz_result[self.current_user]:
                # Password already printed on the Pypykatz module - do not print it again
                self.info('User has already be found: {password}'.format(
                    password=constant.pypykatz_result[self.current_user]['Password'])
                )
                return

        # Password not already found
        pwd_found = []
        if constant.user_dpapi and constant.user_dpapi.unlocked:
            # Check if a password already found is a windows password
            password = constant.user_dpapi.get_cleartext_password()
            if password:
                pwd_found.append({
                    'Login': constant.username,
                    'Password': password
                })
            else:
                # Retrieve dpapi hash used to bruteforce (hash can be retrieved without needed admin privilege)
                # Method taken from Jean-Christophe Delaunay - @Fist0urs
                # https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf

                self.info(
                    u'Windows passwords not found.\n'
                    u'Try to bruteforce this hash (using john or hashcat)'
                )
                if constant.user_dpapi:
                    context = 'local'
                    if self.is_in_domain():
                        context = 'domain'

                    h = constant.user_dpapi.get_dpapi_hash(context=context)
                    if h:
                        pwd_found.append({
                            'Dpapi_hash_{context}'.format(context=context): constant.user_dpapi.get_dpapi_hash(
                                                                                                    context=context)
                        })

        return pwd_found
