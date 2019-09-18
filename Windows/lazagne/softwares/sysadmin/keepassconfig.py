# -*- coding: utf-8 -*- 
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import *

import os

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

        #Keepass1
        connection_file_directory = os.path.join(constant.profile['APPDATA'], u'KeePass')
        if os.path.exists(connection_file_directory):
            connection_file_location = os.path.join(connection_file_directory, u'KeePass.ini')
            if os.path.isfile(connection_file_location):
                file_content = open(connection_file_location, 'r').read()
                #KeeLastDb
                if file_content.partition("KeeLastDb=")[1] == "KeeLastDb=":
                    database = file_content.partition("KeeLastDb=")[2].partition('\n')[0]
                    pwd_found.append({
                        'Keyfile': "No keyfile found",
                        'Database': database
                    })
                if file_content.split("KeeKeySourceID") > 1:
                    KeeKeySource_number = len(file_content.split("KeeKeySourceID")) - 1
                    for i in range(0, KeeKeySource_number ):
                        database = file_content.partition("KeeKeySourceID" + str(i) + "=" )[2].partition('\n')[0]
                        keyfile = file_content.partition("KeeKeySourceValue" + str(i) + "=" )[2].partition('\n')[0]
                        pwd_found.append({
                            'Keyfile': keyfile,
                            'Database': database
                        })  

        #Keepass2
        connection_file_directory = os.path.join(constant.profile['APPDATA'], u'KeePass')
        if os.path.exists(connection_file_directory):
            connection_file_location = os.path.join(connection_file_directory, u'KeePass.config.xml')

            if os.path.isfile(connection_file_location):
                try:
                    connections = parse(connection_file_location).getroot()
                    connection_nodes = connections.findall(".//Association")
                    for connection_node in connection_nodes:
                        database = connection_node.find('DatabasePath').text
                        keyfile = connection_node.find('KeyFilePath').text
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
                        database = connection_node.find('Path').text
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
                        database = connection_node.find('Path').text
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
