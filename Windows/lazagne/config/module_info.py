"""
name => Name of a class
category => windows / browsers / etc
options => dictionary
 - command
 - action
 - dest
 - help

ex: ('-s', action='store_true', dest='skype', help='skype')
- options['command'] = '-s'
- options['action'] = 'store_true'
- options['dest'] = 'skype'
- options['help'] = 'skype'
"""

from lazagne.config.write_output import print_debug


class ModuleInfo(object):

    def __init__(self, name, category, options={}, suboptions=[], registry_used=False, winapi_used=False,
                 system_module=False, dpapi_used=False, only_from_current_user=False):
        self.name = name
        self.category = category
        self.options = {
            'command': '-{name}'.format(name=self.name),
            'action': 'store_true',
            'dest': self.name,
            'help': '{name} passwords'.format(name=self.name)
        }
        self.suboptions = suboptions
        self.registry_used = registry_used
        self.system_module = system_module
        self.winapi_used = winapi_used
        self.dpapi_used = dpapi_used
        self.only_from_current_user = only_from_current_user

    def error(self, message):
        print_debug('ERROR', message)

    def info(self, message):
        print_debug('INFO', message)

    def debug(self, message):
        print_debug('DEBUG', message)

    def warning(self, message):
        print_debug('WARNING', message)