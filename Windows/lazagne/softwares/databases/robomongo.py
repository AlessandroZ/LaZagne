from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
from os.path import isdir, isfile, join
from os import walk
import json

class Robomongo(ModuleInfo):

    def __init__(self):
        options = {'command': '-rbm', 'action': 'store_true', 'dest': 'robomongo', 'help': 'robomongo'}
        ModuleInfo.__init__(self, 'robomongo', 'database', options)
        self.connections_file_location = constant.profile['USERPROFILE'] + "\\.config\\robomongo"
        self.connections_file_name = "robomongo.json"

    def read_file_content(self, file_path):
        """
        Read the content of a file

        :param file_path: Path of the file to read.

        :return: File content as string.
        """
        content = ""
        if isfile(file_path):
            with open(file_path, "r") as file_handle:
                content = file_handle.read()

        return content

    def extract_connections_credentials(self):
        """
        Extract all connection's credentials.

        :return: List of dict in which one dict contains all information for a connection.
        """
        repos_creds = []
        if isdir(self.connections_file_location):
            for (dirpath, dirnames, filenames) in walk(self.connections_file_location, followlinks=True):
                for f in filenames:
                    connection_file_path = join(dirpath, f)
                    if self.connections_file_name in connection_file_path:
                        try:
                            with open(connection_file_path) as connection_file:
                                connections_infos = json.load(connection_file)
                                for connection_infos in connections_infos["connections"]:
                                    creds = {}
                                    creds["Name"] = connection_infos["connectionName"]
                                    creds["Host"] = connection_infos["serverHost"]
                                    creds["Port"] = connection_infos["serverPort"]
                                    if bool(connection_infos["credentials"][0]["enabled"]):
                                        creds["AuthMode"] = "CREDENTIALS"
                                        creds["DatabaseName"] = connection_infos["credentials"][0]["databaseName"]
                                        creds["AuthMechanism"] = connection_infos["credentials"][0]["mechanism"]
                                        creds["Login"] = connection_infos["credentials"][0]["userName"]
                                        creds["Password"] = connection_infos["credentials"][0]["userPassword"]
                                    else:
                                        creds["Host"] = connection_infos["ssh"]["host"]
                                        creds["Port"] = connection_infos["ssh"]["port"]
                                        creds["Login"] = connection_infos["ssh"]["userName"]
                                        if (bool(connection_infos["ssh"]["enabled"]) and
                                                    connection_infos["ssh"]["method"] == "password"):
                                            creds["AuthMode"] = "SSH_CREDENTIALS"
                                            creds["Password"] = connection_infos["ssh"]["userPassword"]
                                        else:
                                            creds["AuthMode"] = "SSH_PRIVATE_KEY"
                                            creds["Passphrase"] = connection_infos["ssh"]["passphrase"]
                                            creds["PrivateKey"] = self.read_file_content(connection_infos["ssh"]["privateKeyFile"])
                                            creds["PublicKey"] = self.read_file_content(connection_infos["ssh"]["publicKeyFile"])
                                    repos_creds.append(creds)
                        except Exception as e:
                            print_debug("ERROR", "Cannot retrieve connections credentials '%s'" % e)
                            pass
        return repos_creds

    def run(self, software_name = None):
        """
        Main function
        """

        # Extract all available connections credentials
        pwd_found = self.extract_connections_credentials()

        return pwd_found
