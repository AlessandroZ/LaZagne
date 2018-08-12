# -*- coding: utf-8 -*- 
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant
from lazagne.config.winstructure import *


class Credman(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'credman', 'windows', exec_at_end=True)

    def run(self):
        pwd_found = []

        if constant.user_dpapi.unlocked:
            creds_directory = os.path.join(constant.profile['APPDATA'], u'Microsoft', u'Credentials')
            if os.path.exists(creds_directory):
                for cred_file in os.listdir(creds_directory):
                    # decrypting creds files (Credman module not allow to retrieve domain password)
                    cred = constant.user_dpapi.decrypt_cred(os.path.join(creds_directory, cred_file))
                    if cred:
                        pwd_found.append(cred)

         # check if executed from current user (otherwise, Windows API cannot be called)
        elif constant.is_current_user:
            # FOR XP
            # - password are encrypted with specific salt depending on its Type
            # entropy = 'abe2869f-9b47-4cd9-a358-c22904dba7f7\0' # FOR CRED_TYPE_GENERIC
            # entropy = '82BD0E67-9FEA-4748-8672-D5EFE5B779B0\0' # FOR CRED_TYPE_DOMAIN_VISIBLE_PASSWORD
            # CryptUnprotectData(byref(blobIn), None, byref(blobEntropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, byref(blobOut))

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
                                'Password': c.CredentialBlob[:c.CredentialBlobSize.real].replace('\x00', '')
                            })

                CredFree(creds)
        return pwd_found
