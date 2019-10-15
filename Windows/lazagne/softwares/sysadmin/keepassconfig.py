# -*- coding: utf-8 -*- 
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import *

import os

from xml.etree.ElementTree import parse

class KeePassConfig(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'keepassconfig', 'sysadmin')
        self.attr_to_extract = ["Keyfile", "Database", "Type"]

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
                #KeeKeySourceID
                if len(file_content.split("KeeKeySourceID")) > 1:
                    KeeKeySource_number = len(file_content.split("KeeKeySourceID")) - 1
                    for i in range(0, KeeKeySource_number ):
                        database = file_content.partition("KeeKeySourceID" + str(i) + "=" )[2].partition('\n')[0]
                        database = database.replace('..\\..\\', 'C:\\')
                        keyfile = file_content.partition("KeeKeySourceValue" + str(i) + "=" )[2].partition('\n')[0]
                        pwd_found.append({
                            'Keyfile': keyfile,
                            'Database': database
                        })  
                #KeeLastDb
                if file_content.partition("KeeLastDb=")[1] == "KeeLastDb=":
                    database = file_content.partition("KeeLastDb=")[2].partition('\n')[0]
                    database = database.replace('..\\..\\', 'C:\\')
                    already_in_pwd_found = 0
                    for elmt in pwd_found:
                        if database == elmt['Database']:
                            already_in_pwd_found = 1
                    if already_in_pwd_found == 0:
                        pwd_found.append({
                            'Keyfile': "No keyfile found",
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
                        database = connection_node.find('DatabasePath').text.replace('..\\..\\', 'C:\\')
                        type = ""
                        if connection_node.find('Password') is not None:
                            type += "Password - "
                        if  connection_node.find('UserAccount') is not None:
                            type += "NTLM - "
                        try:
                            keyfile = connection_node.find('KeyFilePath').text.replace('..\\..\\', 'C:\\')
                            type += "Keyfile - "
                        except:
                            keyfile = "No keyfile found"

                        pwd_found.append({
                            'Keyfile': keyfile,
                            'Database': database,
							'Type': type[:-3]
                        })
                except:
                    pass

                try:
                    connections = parse(connection_file_location).getroot()
                    connection_nodes = connections.findall(".//LastUsedFile")
                    for connection_node in connection_nodes:
                        database = connection_node.find('Path').text.replace('..\\..\\', 'C:\\')
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
                        database = connection_node.find('Path').text.replace('..\\..\\', 'C:\\')
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
