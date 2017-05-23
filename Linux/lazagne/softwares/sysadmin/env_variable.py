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
        known_tokens = set()

        blacklist = (
            'PWD', 'OLDPWD', 'SYSTEMD_NSS_BYPASS_BUS'
        )

        proxies = (
            'http_proxy', 'https_proxy',
            'HTTP_Proxy', 'HTTPS_Proxy',
            'HTTP_PROXY', 'HTTPS_PROXY'
        )

        tokens = (
            ('DigitalOcean', {
                'ID': None,
                'KEY': 'DIGITALOCEAN_ACCESS_TOKEN',
            }),
            ('DigitalOcean', {
                'ID': None,
                'KEY': 'DIGITALOCEAN_API_KEY'
            }),
            ('AWS', {
                'ID': 'AWS_ACCESS_KEY_ID',
                'KEY': 'AWS_SECRET_ACCESS_KEY',
            }),
            ('AWS', {
                'ID': 'EC2_ACCESS_KEY',
                'KEY': 'EC2_SECRET_KEY'
            }),
            ('GitHub', {
                'ID': 'GITHUB_CLIENT',
                'KEY': 'GITHUB_SECRET'
            }),
            ('GitHub', {
                'ID': None,
                'KEY': 'GITHUB_TOKEN',
            }),
            ('OpenStack', {
                'ID': 'OS_USERNAME',
                'KEY': 'OS_PASSWORD'
            })
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
                    pw = {
                        'Login': parsed.username,
                        'Password': parsed.password,
                        'Host': parsed.hostname,
                    }
                    if parsed.port:
                        pw.update({
                            'Port': parsed.port
                        })

                    pwdFound.append(pw)

            for token, kvars in tokens:
                if not kvars['KEY'] in environ:
                    continue

                secret = environ[kvars['KEY']]

                if secret in known_tokens:
                    continue

                pw = {
                    'Service': token,
                    'KEY': secret
                }

                if kvars['ID'] and kvars['ID'] in environ:
                    pw.update({'ID': environ[kvars['ID']]})

                pwdFound.append(pw)

                known_tokens.add(secret)

            for i in environ:
                for t in ['passwd', 'pwd', 'pass', 'password']:
                    if (t.upper() in i.upper()) and (i.upper() not in blacklist):
                        pwdFound.append({
                            'Login': i,
                            'Password': environ[i]
                        })

        return pwdFound
