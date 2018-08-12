# -*- coding: utf-8 -*- 
from xml.etree.ElementTree import parse

from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import *

import os


class ApacheDirectoryStudio(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'apachedirectorystudio', 'sysadmin')
        # Interesting XML attributes in ADS connection configuration
        self.attr_to_extract = ["host", "port", "bindPrincipal", "bindPassword", "authMethod"]

    def extract_connections_credentials(self):
        """
        Extract all connection's credentials.

        :return: List of dict in which one dict contains all information for a connection.
        """
        repos_creds = []
        connection_file_location = os.path.join(
            constant.profile["USERPROFILE"],
            u'.ApacheDirectoryStudio\\.metadata\\.plugins\\org.apache.directory.studio.connection.core\\connections.xml'
        )
        if os.path.isfile(connection_file_location):
            try:
                connections = parse(connection_file_location).getroot()
                connection_nodes = connections.findall(".//connection")
                for connection_node in connection_nodes:
                    creds = {}
                    for connection_attr_name in connection_node.attrib:
                        if connection_attr_name in self.attr_to_extract:
                            creds[connection_attr_name] = connection_node.attrib[connection_attr_name].strip()
                    if creds:
                        repos_creds.append(creds)
            except Exception as e:
                self.error(u"Cannot retrieve connections credentials '%s'" % e)

        return repos_creds

    def run(self):
        """
        Main function
        """
        # Extract all available connections credentials
        repos_creds = self.extract_connections_credentials()

        # Parse and process the list of connections credentials
        pwd_found = []
        for creds in repos_creds:
            pwd_found.append({
                "Host"                  : creds["host"],
                "Port"                  : creds["port"],
                "Login"                 : creds["bindPrincipal"],
                "Password"              : creds["bindPassword"],
                "AuthenticationMethod"  : creds["authMethod"]
            })

        return pwd_found
