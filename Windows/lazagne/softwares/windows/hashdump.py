# -*- coding: utf-8 -*-
from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo

from .creddump7.win32.hashdump import dump_file_hashes


class Hashdump(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'hashdump', 'windows', system_module=True)

    def run(self):
        hashdump = dump_file_hashes(
            constant.hives['system'], constant.hives['sam'])
        if hashdump:
            pwd_found = ['__Hashdump__', hashdump]
            return pwd_found
