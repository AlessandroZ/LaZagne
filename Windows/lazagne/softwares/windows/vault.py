# -*- coding: utf-8 -*-
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import *
from ctypes.wintypes import *


class Vault(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'vault', 'windows',  only_from_current_user=True)

    def run(self):

        # retrieve passwords (IE, etc.) using the Windows Vault API
        if float(get_os_version()) < 6.1:
            self.info(u'Vault not supported for this OS')
            return

        cbVaults = DWORD()
        vaults = LPGUID()
        hVault = HANDLE(INVALID_HANDLE_VALUE)
        cbItems = DWORD()
        items_buf = c_char_p()
        pwd_found = []

        if vaultEnumerateVaults(0, byref(cbVaults), byref(vaults)) == 0:
            if cbVaults.value == 0:
                self.debug(u'No Vaults found')
                return
            else:
                VAULT_ITEM_WIN, PVAULT_ITEM_WIN, VaultGetItemFunc = get_vault_objects_for_this_version_of_windows()
                for i in range(cbVaults.value):
                    if vaultOpenVault(byref(vaults[i]), 0, byref(hVault)) == 0:
                        if hVault:
                            if vaultEnumerateItems(hVault, 0x200, byref(cbItems), byref(items_buf)) == 0:

                                for j in range(cbItems.value):

                                    items = cast(items_buf, POINTER(VAULT_ITEM_WIN))
                                    pPasswordVaultItem = PVAULT_ITEM_WIN()
                                    try:
                                        values = {
                                            'URL': str(items[j].pResource.contents.data.string),
                                            'Login': str(items[j].pUsername.contents.data.string)
                                        }
                                        if items[j].pName:
                                            values['Name'] = items[j].pName

                                        if VaultGetItemFunc(hVault, items[j], pPasswordVaultItem) == 0:

                                            password = pPasswordVaultItem.contents.pPassword.contents.data.string
                                            # Remove password too long
                                            if password and len(password) < 100:
                                                values['Password'] = password

                                        pwd_found.append(values)

                                    except Exception as e:
                                        self.debug(e)

                                    if pPasswordVaultItem:
                                        vaultFree(pPasswordVaultItem)

                                if items_buf:
                                    vaultFree(items_buf)

                            vaultCloseVault(byref(hVault))

                vaultFree(vaults)

        return pwd_found
