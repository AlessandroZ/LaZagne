# -*- coding: utf-8 -*-
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant
import os


class VaultFiles(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'vaultfiles', 'windows', dpapi_used=True)

    def run(self):

        pwd_found = []
        if constant.user_dpapi and constant.user_dpapi.unlocked:
            main_vault_directory = os.path.join(constant.profile['APPDATA'], u'..', u'Local', u'Microsoft', u'Vault')
            main_vault_directory =  os.path.abspath(main_vault_directory)
            if os.path.exists(main_vault_directory):
                for vault_directory in os.listdir(main_vault_directory):
                    cred = constant.user_dpapi.decrypt_vault(os.path.join(main_vault_directory, vault_directory))
                    if cred:
                        pwd_found.append(cred)

        return pwd_found
