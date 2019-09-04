# -*- coding: utf-8 -*- 
from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import *
from lazagne.config import homes

import os

try:
    from ConfigParser import RawConfigParser  # Python 2.7
except ImportError:
    from configparser import RawConfigParser  # Python 3

class gFTP(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'gftp', 'sysadmin')
        self.attr_to_extract = ["host", "port", "username", "password", "protocol", "account", "entry"]

    def decode_password(self, encoded_pass):
        """
        Password is offuscated: first char is a $. Then each char from the password is converted in hex and encoded regarding its value
        """
        decoded_pass = ""
        #removing the first char ($)
        encoded_pass = encoded_pass[1:]
        password_offuscation_table = ['A', 'E', 'I', 'M', 'Q', 'U', 'Y', ']', 'a', 'e', 'i', 'm', 'q', 'u', 'y', '}']
        chars = [encoded_pass[i:i + 2] for i in range(0, len(encoded_pass), 2)]

        for char in chars:
            decoded_pass += chr(password_offuscation_table.index(char[0]) * 16 + password_offuscation_table.index(char[1]))
        return decoded_pass

    def get_parameter(self, name, file_content):
        """
        Get the parameter name in a file (file_content)
        """
        return file_content.partition(name)[2].partition('\n')[0][1:]

    def run(self):
        """
        Main function
        """

        # Extract all available connections credentials
        pwd_found = []
        for connection_file_directory in homes.get(directory=u'.gftp'):
            connection_file_location = os.path.join(connection_file_directory, u'bookmarks')

            if os.path.isfile(connection_file_location):
                cp = RawConfigParser()
                cp.read(connection_file_location)
                for elmt in cp.sections():
                    username = cp.get(elmt, "username")
                if username != "anonymous":
                    host = cp.get(elmt, "hostname")
                    port = cp.get(elmt, "port")
                    protocol = cp.get(elmt, "protocol")
                    password = self.decode_password(cp.get(elmt, "password"))
                    account =cp.get(elmt, "account")
                    pwd_found.append({
                        'Entry': "Server",
                        'Host': host,
                        'Username': username,
                        'Password': password,
                        'Port': port,
                        'Protocol': protocol,
                        'Account': account,

                    })
            # Extract Proxy data from another file
            connection_file_location = os.path.join(connection_file_directory, u'gftprc')
            if os.path.isfile(connection_file_location):
                preferences = open(connection_file_location, 'r').read()
                # FTP Proxy
                ftp_proxy_host = self.get_parameter("ftp_proxy_host", preferences)
                if ftp_proxy_host != "":
                    ftp_proxy_port = self.get_parameter("ftp_proxy_port", preferences)
                    ftp_proxy_username = self.get_parameter("ftp_proxy_username", preferences)
                    ftp_proxy_password = self.get_parameter("ftp_proxy_password", preferences)
                    ftp_proxy_account = self.get_parameter("ftp_proxy_account", preferences)
                    if ftp_proxy_username != "" and ftp_proxy_password != "":
                        pwd_found.append({
                            'Entry': 'FTP Proxy',
                            'Protocol': 'FTP',
                            'Host': ftp_proxy_host,
                            'Port': ftp_proxy_port,
                            'Username': ftp_proxy_username,
                            'Password': ftp_proxy_password,
                            'Account': ftp_proxy_account
                        })
                
                # HTTP Proxy
                http_proxy_host = self.get_parameter("http_proxy_host", preferences)
                if http_proxy_host != "":
                    http_proxy_port = self.get_parameter("http_proxy_port", preferences)
                    http_proxy_username = self.get_parameter("http_proxy_username", preferences)
                    http_proxy_password = self.get_parameter("http_proxy_password", preferences)
                    http_proxy_account = self.get_parameter("http_proxy_account", preferences)
                    if http_proxy_username != "" and http_proxy_password != "":
                        pwd_found.append({
                            'Entry': "HTTP Proxy",
                            'Protocol': "HTTP",
                            'Host': http_proxy_host,
                            'Port': http_proxy_port,
                            'Username': http_proxy_username,
                            'Password': http_proxy_password,
                            'Account': http_proxy_account
                        })
            
        return pwd_found
