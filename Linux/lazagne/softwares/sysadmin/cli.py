from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config import homes
from ConfigParser import ConfigParser

import psutil
import os
import pwd

class Cli(ModuleInfo):
    def __init__(self):
        options = {'command': '-C', 'action': 'store_true', 'dest': 'cli', 'help': 'cli'}
        suboptions = []
        ModuleInfo.__init__(self, 'cli', 'sysadmin', options, suboptions)

    def get_files(self):
        known = set()
        for user, histfile in homes.users(file=['.history', '.sh_history', '.bash_history', '.zhistory']):
            yield user, histfile
            known.add(histfile)

        for process in psutil.process_iter():
            try:
                environ = process.environ()
                user = process.username()
            except:
                continue

            if not 'HISTFILE' in environ:
                continue

            histfile = environ['HISTFILE']

            if histfile in ('/dev/zero', '/dev/null'):
                continue

            if histfile.startswith('~/'):
                try:
                    home = pwd.getpwuid(process.uids().effective).pw_dir
                except:
                    continue

                histfile = os.path.join(home, histfile[2:])

            if os.path.isfile(histfile) and not histfile in known:
                yield user, histfile
                known.add(histfile)

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
                        except:
                            pass

                        line = ' '.join(x for x in line.split() if x)
                        if not line in known:
                            yield user, line
                            known.add(line)
            except:
                pass

        for user, histfile in homes.users(file='.local/share/mc/history'):
            parser = ConfigParser()
            try:
                parser.read(histfile)
            except:
                continue

            try:
                for i in parser.options('cmdline'):
                    line = parser.get('cmdline', i)
                    if not line in known:
                        yield user, line
                        known.add(line)
            except:
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
            ('wget', '-password')
        ]

        for marker in markers:
            if all((x in line) for x in marker):
                yield {
                    'User': user,
                    'Cmd': line
                }

    def run(self, software_name=None):
        all_cmds = []
        for user, line in self.get_lines():
            for cmd in self.suspicious(user, line):
                all_cmds.append(cmd)
        return all_cmds
