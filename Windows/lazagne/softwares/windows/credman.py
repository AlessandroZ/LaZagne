# -*- coding: utf-8 -*- 
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import *


class Credman(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'credman', 'windows', only_from_current_user=True)

    def run(self):
        pwd_found = []
        # FOR XP
        # - password are encrypted with specific salt depending on its Type
        # entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\\0' # FOR CRED_TYPE_GENERIC
        # entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\\0' # FOR CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
        # CryptUnprotectData(byref(blobIn),None,byref(blobEntropy),None,None,CRYPTPROTECT_UI_FORBIDDEN,byref(blobOut))

        creds = POINTER(PCREDENTIAL)()
        count = c_ulong()

        if CredEnumerate(None, 0, byref(count), byref(creds)) == 1:
            for i in range(count.value):
                c = creds[i].contents
                if c.Type == CRED_TYPE_GENERIC or c.Type == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD:
                    # Remove password too long
                    if c.CredentialBlobSize.real < 200:
                        pwd_found.append({
                            'URL': c.TargetName,
                            'Login': c.UserName,
                            'Password': c.CredentialBlob[:c.CredentialBlobSize.real].replace(b"\x00", b"")
                        })

            CredFree(creds)
        return pwd_found
