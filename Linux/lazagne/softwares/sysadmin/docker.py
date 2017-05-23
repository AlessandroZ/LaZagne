from lazagne.config.constant import *
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config import homes

import json

import os

class Docker(ModuleInfo):
    def __init__(self):
        options = {'command': '-D', 'action': 'store_true', 'dest': 'docker', 'help': 'docker'}
        suboptions = []
        ModuleInfo.__init__(self, 'docker', 'sysadmin', options, suboptions)

    def get_paths(self):
        return homes.get(file=os.path.join('.docker', 'config.json'))

    def get_creds(self, path):
        try:
            with open(path) as config:
                config = json.load(config)
                if not 'auths' in config:
                    return

                for hub, auth in config['auths'].iteritems():
                    user, password = auth['auth'].decode('base64').split(':', 1)
                    yield hub, user, password
                    
                    
        except:
            return
            

    def run(self, software_name=None):
        all_passwords = []
        for path in self.get_paths():
            for hub, user, password in self.get_creds(path):
                all_passwords.append({
                    'User': user,
                    'Password': password,
                    'Hub': hub,
                })

        return all_passwords
