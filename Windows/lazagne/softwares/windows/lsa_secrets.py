# -*- coding: utf-8 -*- 
import struct

from .creddump7.win32.lsasecrets import get_file_secrets
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import get_os_version
from lazagne.config.constant import constant


class LSASecrets(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'lsa_secrets', 'windows', system_module=True)

    def run(self):

        # DPAPI structure could compute lsa secrets as well, so do not do it again
        if constant.lsa_secrets:
            return ['__LSASecrets__', constant.lsa_secrets]

        is_vista_or_higher = False
        if float(get_os_version()) >= 6.0:
            is_vista_or_higher = True

        # Get LSA Secrets
        secrets = get_file_secrets(constant.hives['system'], constant.hives['security'], is_vista_or_higher)
        if secrets:
            # Clear DPAPI master key 
            clear = secrets[b'DPAPI_SYSTEM']
            size = struct.unpack_from("<L", clear)[0]
            secrets[b'DPAPI_SYSTEM'] = clear[16:16 + 44]

            # Keep value to be reused in other module (e.g wifi)
            constant.lsa_secrets = secrets
            return ['__LSASecrets__', secrets]
