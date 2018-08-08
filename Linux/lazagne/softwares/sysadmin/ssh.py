#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes


class Ssh(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'ssh', 'sysadmin')

    def get_ids(self):
        known = set()
        for user, identity in homes.users(file=[
            os.path.join('.ssh', item) for item in (
                    'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'
            )
        ]):
            if os.path.isfile(identity):
                try:
                    with open(identity) as fidentity:
                        yield {
                            'KEY': fidentity.read(),
                            'User': user,
                        }
                        known.add(identity)
                except Exception:
                    pass

        for user, config in self.get_configs():
            for pw in self.get_ids_from_config(user, config):
                if pw['KEY'] in known:
                    continue

                try:
                    with open(pw['KEY']) as fidentity:
                        pw['KEY'] = fidentity.read()
                        yield pw
                        known.add(identity)
                except Exception:
                    pass

    def get_configs(self):
        return homes.users(file=os.path.join('.ssh', 'config'))

    def create_pw_object(self, identity, host, port, user):
        pw = {'KEY': identity}
        if host:
            pw['Host'] = host
        if port:
            pw['Port'] = port
        if user:
            pw['Login'] = user
        return pw

    def get_ids_from_config(self, default_user, config):
        try:
            hostname = None
            port = 22
            user = default_user
            identity = None

            with open(config) as fconfig:
                for line in fconfig.readlines():
                    line = line.strip()

                    if line.startswith('#'):
                        continue

                    line = line.split()
                    if len(line) < 2:
                        continue

                    cmd, args = line[0].lower(), line[1:]
                    args = ' '.join([x for x in args if x])

                    if cmd == 'host':
                        if identity:
                            yield self.create_pw_object(
                                identity, hostname, port, user
                            )

                        hostname = None
                        port = 22
                        user = default_user
                        identity = None

                    elif cmd == 'hostname':
                        hostname = args

                    elif cmd == 'user':
                        user = args

                    elif cmd == 'identityfile':
                        if args.startswith('~/'):
                            args = config[:config.find('.ssh')] + args[2:]
                        identity = args

            if identity:
                yield self.create_pw_object(
                    identity, hostname, port, user
                )

        except Exception as e:
            pass

    def run(self):
        return list(self.get_ids())
