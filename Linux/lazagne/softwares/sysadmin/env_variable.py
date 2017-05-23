#!/usr/bin/env python
import os
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo

import psutil
import urlparse

class Env_variable(ModuleInfo):
    def __init__(self):
        options = {'command': '-e', 'action': 'store_true', 'dest': 'env', 'help': 'environment variables'}
        ModuleInfo.__init__(self, 'Environment variables', 'sysadmin', options)

    def run(self, software_name = None):
        pwdFound = []

        known_proxies = set()

        blacklist = (
            'PWD', 'OLDPWD', 'SYSTEMD_NSS_BYPASS_BUS'
        )

        proxies = (
            'http_proxy', 'https_proxy',
            'HTTP_Proxy', 'HTTPS_Proxy',
            'HTTP_PROXY', 'HTTPS_PROXY'
        )

        for process in psutil.process_iter():
            try:
                environ = process.environ()
            except:
                continue

            for var in proxies:
                if not var in environ or environ[var] in known_proxies:
                    continue

                proxy = environ[var]
                known_proxies.add(proxy)

                try:
                    parsed = urlparse.urlparse(proxy)
                except:
                    continue

                if parsed.username and parsed.password:
                    pwdFound.append({
                        'Login': parsed.username,
                        'Password': parsed.password,
                        'Host': parsed.hostname,
                        'Port': parsed.port
                    })

            for i in environ:
                for t in ['passwd', 'pwd', 'pass', 'password']:
                    if (t.upper() in i.upper()) and (i.upper() not in blacklist):
                        pwdFound.append({
                            'Login': i,
                            'Password': environ[i]
                        })

        return pwdFound
