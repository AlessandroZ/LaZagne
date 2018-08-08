# -*- coding: utf-8 -*- 
import os
import re
from xml.etree.cElementTree import ElementTree

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo


class RoguesTale(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'roguestale', 'games')

    def run(self):
        creds = []
        directory = constant.profile['USERPROFILE'] + u'\\Documents\\Rogue\'s Tale\\users'

        # The actual user details are stored in *.userdata files
        if os.path.exists(directory):
            files = os.listdir(directory)

            for f in files:
                if re.match('.*\.userdata', f):
                    # We've found a user file, now extract the hash and username

                    xmlfile = directory + '\\' + f
                    tree = ElementTree(file=xmlfile)
                    root = tree.getroot()

                    # Double check to make sure that the file is valid
                    if root.tag != 'user':
                        self.warning(u'Profile %s does not appear to be valid' % f)
                        continue

                    # Now save it to credentials
                    creds.append({
                        'Login': root.attrib['username'],
                        'Hash': root.attrib['password']
                    })

            return creds
