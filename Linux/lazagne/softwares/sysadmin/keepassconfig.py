# -*- coding: utf-8 -*- 
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import *
from lazagne.config import homes

import os

try:
    from ConfigParser import RawConfigParser  # Python 2.7
except ImportError:
    from configparser import RawConfigParser  # Python 3

from xml.etree.ElementTree import parse

class KeePassConfig(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'keepassconfig', 'sysadmin')
        self.attr_to_extract = ["Keyfile", "Database"]

    def run(self):
        """
        Main function
        """

        pwd_found = []

        #KeepassX
        for connection_file_directory in homes.get(directory=u'.config/keepassx'):
            #Used to replace ./ by the home path
            home = connection_file_directory.partition('./config')[0]
            connection_file_location = os.path.join(connection_file_directory, u'config.ini')

            if os.path.isfile(connection_file_location):
                cp = RawConfigParser()
                cp.read(connection_file_location)
                try:
                    database = cp.get("Options", "LastFile").replace('./',  home)
                    keyfile = cp.get("Options", "LastKeyLocation").replace('./',  home)
                    keytype = cp.get("Options", "LastKeyType")
                    if keytype == "Password":
                        keyfile = "No keyfile needed"
                    elif keyfile == "":
                        keyfile = "No keyfile found"
                    pwd_found.append({
                        'Keyfile': keyfile,
                        'Database': database
                    })
                except:
                    pass

        #Keepass2

        for connection_file_directory in homes.get(directory=u'.config/KeePass'):
            home = connection_file_directory.partition('./config')[0]
            connection_file_location = os.path.join(connection_file_directory, u'KeePass.config.xml')

            if os.path.isfile(connection_file_location):
                try:
                    connections = parse(connection_file_location).getroot()
                    connection_nodes = connections.findall(".//Association")
                    for connection_node in connection_nodes:
                        database = connection_node.find('DatabasePath').text.replace("../../../", home)
                        keyfile = connection_node.find('KeyFilePath').text.replace("../../../", home)
                        pwd_found.append({
                            'Keyfile': keyfile,
                            'Database': database
                        })
                except:
                    pass

                try:
                    connections = parse(connection_file_location).getroot()
                    connection_nodes = connections.findall(".//LastUsedFile")
                    for connection_node in connection_nodes:
                        database = connection_node.find('Path').text.replace("../../../", home)
                        already_in_pwd_found = 0
                        for elmt in pwd_found:
                            if database == elmt['Database']:
                                already_in_pwd_found = 1
                        if already_in_pwd_found == 0:
                            pwd_found.append({
                                'Keyfile': "No keyfile found",
                                'Database': database
                            })
                except:
                    pass

                try:
                    connections = parse(connection_file_location).getroot()
                    connection_nodes = connections.findall(".//ConnectionInfo")
                    for connection_node in connection_nodes:
                        database = connection_node.find('Path').text.replace("../../../", home)
                        already_in_pwd_found = 0
                        for elmt in pwd_found:
                            if database == elmt['Database']:
                                already_in_pwd_found = 1
                        if already_in_pwd_found == 0:
                            pwd_found.append({
                                'Keyfile': "No keyfile found",
                                'Database': database
                            })
                except:
                    pass

        return pwd_found