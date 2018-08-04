from lazagne.config.moduleInfo import ModuleInfo
from lazagne.softwares.browsers.mozilla import Mozilla
import os


class Thunderbird(Mozilla):

    def __init__(self):
        self.path = '~/.thunderbird'
        ModuleInfo.__init__(self, 'Thunderbird', 'mails')
