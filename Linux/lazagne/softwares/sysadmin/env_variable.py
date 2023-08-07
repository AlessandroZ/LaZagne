#!/usr/bin/env python
# -*- coding: utf-8 -*-
import psutil

from lazagne.config.module_info import ModuleInfo

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


class Env_variable(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'Environment variables', 'sysadmin')

    def run(self):
        pwd_found = []
        known_proxies = set()
        known_tokens = set()

        blacklist = (
            'PWD', 'OLDPWD', 'SYSTEMD_NSS_BYPASS_BUS', 'SYSTEMD_NSS_DYNAMIC_BYPASS'
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

        try:
            for process in psutil.process_iter():
                try:
                    environ = process.environ()
                except Exception:
                    continue

                for var in proxies:
                    if var not in environ or environ[var] in known_proxies:
                        continue

                    proxy = environ[var]
                    known_proxies.add(proxy)

                    try:
                        parsed = urlparse.urlparse(proxy)
                    except Exception:
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

                        pwd_found.append(pw)

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

                    pwd_found.append(pw)
                    known_tokens.add(secret)

                for i in environ:
                    for t in ['passwd', 'pwd', 'pass', 'password']:
                        if (t.upper() in i.upper()) and (i.upper() not in blacklist):
                            pwd_found.append({
                                'Login': i,
                                'Password': environ[i]
                            })

            return pwd_found

        except AttributeError:
            # Fix AttributeError: 'module' object has no attribute 'process_iter'
            pass
