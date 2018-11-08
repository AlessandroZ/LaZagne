#!/usr/bin/env python
# -*- coding: utf-8 -*- 

import psutil
import pwd
import os

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes

try:
    from ConfigParser import ConfigParser  # Python 2.7
except ImportError:
    from configparser import ConfigParser  # Python 3


class Cli(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'cli', 'sysadmin')

    def get_files(self):
        known = set()
        for user, histfile in homes.users(file=['.history', '.sh_history', '.bash_history', '.zhistory']):
            yield user, histfile
            known.add(histfile)

        try:
            for process in psutil.process_iter():
                try:
                    environ = process.environ()
                    user = process.username()
                except Exception:
                    continue

                if 'HISTFILE' not in environ:
                    continue

                histfile = environ['HISTFILE']

                if histfile in ('/dev/zero', '/dev/null'):
                    continue

                if histfile.startswith('~/'):
                    try:
                        home = pwd.getpwuid(process.uids().effective).pw_dir
                    except Exception:
                        continue

                    histfile = os.path.join(home, histfile[2:])

                if os.path.isfile(histfile) and not histfile in known:
                    yield user, histfile
                    known.add(histfile)

        except AttributeError:
            # Fix AttributeError: 'module' object has no attribute 'process_iter'
            pass

    def get_lines(self):
        known = set()
        for user, plainfile in self.get_files():
            try:
                with open(plainfile) as infile:
                    for line in infile.readlines():
                        line = line.strip()
                        if line.startswith('#'):
                            continue
                        try:
                            int(line)
                            continue
                        except Exception:
                            pass

                        line = ' '.join(x for x in line.split() if x)
                        if line not in known:
                            yield user, line
                            known.add(line)
            except Exception:
                pass

        for user, histfile in homes.users(file='.local/share/mc/history'):
            parser = ConfigParser()
            try:
                parser.read(histfile)
            except Exception:
                continue

            try:
                for i in parser.options('cmdline'):
                    line = parser.get('cmdline', i)
                    if line not in known:
                        yield user, line
                        known.add(line)
            except Exception:
                pass

    def suspicious(self, user, line):
        markers = [
            ('sshpass', '-p'),
            ('chpasswd',),
            ('openssl', 'passwd'),
            ('sudo', '-S'),
            ('mysql', '-p'),
            ('psql', 'postgresql://'),
            ('pgcli', 'postgresql://'),
            ('ssh', '-i'),
            ('sqlplus', '/'),
            ('xfreerdp', '/p'),
            ('vncviewer', 'passwd'),
            ('vncviewer', 'PasswordFile'),
            ('mount.cifs', 'credentials'),
            ('pass=',),
            ('smbclient',),
            ('ftp', '@'),
            ('wget', '@'),
            ('curl', '@'),
            ('curl', '-u'),
            ('wget', '-password'),
            ('rdesktop', '-p'),
        ]

        for marker in markers:
            if all((x in line) for x in marker):
                yield {
                    'User': user,
                    'Cmd': line
                }

    def run(self):
        all_cmds = []
        for user, line in self.get_lines():
            for cmd in self.suspicious(user, line):
                all_cmds.append(cmd)
        return all_cmds
