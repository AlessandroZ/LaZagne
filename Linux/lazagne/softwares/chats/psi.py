# -*- coding: utf-8 -*- 
import os
from xml.etree.cElementTree import ElementTree
from itertools import cycle

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes


class PSI(ModuleInfo):
    def __init__(self):
        self.pwd_found = []

        ModuleInfo.__init__(self, 'psi-im', 'chats')

    def get_profiles_files(self):
        for profile_dir in homes.get(directory=[u'.config/psi/profiles', u'.local/psi+/profiles']):
            try:
                subdirs = os.listdir(profile_dir)
            except Exception:
                continue

            for subdir in subdirs:
                login_data = os.path.join(profile_dir, subdir, 'accounts.xml')
                if os.path.isfile(login_data):
                    yield login_data

    # Thanks to https://github.com/jose1711/psi-im-decrypt
    def decode_password(self, password, jid):
        result = ''
        jid = cycle(jid)
        for n1 in range(0, len(password), 4):
            x = int(password[n1:n1 + 4], 16)
            result += chr(x ^ ord(next(jid)))

        return result

    def process_one_file(self, _path):
        root = ElementTree(file=_path).getroot()

        for item in root:
            if item.tag == '{http://psi-im.org/options}accounts':
                for acc in item:
                    values = {}

                    for x in acc:
                        if x.tag == '{http://psi-im.org/options}jid':
                            values['Login'] = x.text

                        elif x.tag == '{http://psi-im.org/options}password':
                            values['Password'] = x.text

                    values['Password'] = self.decode_password(values['Password'], values['Login'])

                    if values:
                        self.pwd_found.append(values)

    def run(self):
        for one_file in self.get_profiles_files():
            self.process_one_file(one_file)

        return self.pwd_found
