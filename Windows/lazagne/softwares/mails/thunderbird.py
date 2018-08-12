from lazagne.config.module_info import ModuleInfo
from lazagne.softwares.browsers.mozilla import Mozilla


class Thunderbird(Mozilla):

    def __init__(self):
        self.path = u'{APPDATA}\\Thunderbird'
        ModuleInfo.__init__(self, 'Thunderbird', 'mails')
