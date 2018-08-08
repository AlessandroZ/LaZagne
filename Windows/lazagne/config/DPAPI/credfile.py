#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from .structures import *
from .blob import *


class CredFile():
    """
    Decrypt Credentials Files stored on ...\Microsoft\Credentials\...
    """

    def __init__(self, credfile):
        self.credfile = credfile
        credfile_parsed = CREDENTIAL_FILE.parse(open(credfile, 'rb').read())
        self.blob = DPAPIBlob(credfile_parsed.blob)

    def decrypt(self, mkp):
        ok, msg = self.blob.decrypt_encrypted_blob(mkp=mkp)
        if ok:
            cred_dec = CREDENTIAL_DECRYPTED.parse(msg)
            if cred_dec.header.unk_type == 3:
                return True, {
                    'File': '{file}'.format(file=self.credfile),
                    'Domain': '{domain}'.format(domain=cred_dec.main.domain.data),
                    'Username': '{username}'.format(username=cred_dec.main.username.data),
                    'Password': '{password}'.format(password=cred_dec.main.password.data),
                }
            # system type
            elif cred_dec.header.unk_type == 2:
                return False, 'System credential type'
            else:
                return False, 'Unknown CREDENTIAL type, please report.\nCreds: {creds}'.format(creds=cred_dec)
        else:
            return ok, msg
