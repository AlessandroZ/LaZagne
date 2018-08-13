# -*- coding: utf-8 -*- 
# Thanks to the awesome work done by harmjoy
# For more information http://www.harmj0y.net/blog/redteaming/keethief-a-case-study-in-attacking-keepass-part-2/

# Thanks for the great work of libkeepass (used to decrypt keepass file)
# https://github.com/phpwutz/libkeepass

import traceback

from . import libkeepass
from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo


class Keepass(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'keepass', 'memory')

    def run(self):
        # password found on the memory dump class
        if constant.keepass:
            res = []
            for db in constant.keepass:
                try:
                    with libkeepass.open(db.values()[0][u'Database'],
                                         password=db.get(u"KcpPassword", {}).get(u'Password'),
                                         keyfile=db.get(u"KcpKeyFile", {}).get(u'KeyFilePath')) as kdb:
                        res.extend(kdb.to_dic())
                except Exception:
                    self.debug(traceback.format_exc())
            return res
