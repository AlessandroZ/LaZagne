import os
import json
from lazagne.config.constant import *
from lazagne.config.moduleInfo import ModuleInfo

class Composer(ModuleInfo):

    def __init__(self):
        options = {'command': '-phpcomp', 'action': 'store_true', 'dest': 'composer', 'help': 'PHP Composer'}
        ModuleInfo.__init__(self, 'composer', 'php', options)

    def extract_credentials(self, location):
        """
        Extract the credentials from the "auth.json" file.
        See "https://getcomposer.org/doc/articles/http-basic-authentication.md" for file format.
        :param location: Full path to the "auth.json" file
        :return: List of credentials founds
        """
        creds_found = []

        if os.path.isfile(location):
            with open(location) as f:
                creds = json.load(f)
                for cred_type in creds:
                    for domain in creds[cred_type]:
                        values = {}
                        values["AuthenticationType"] = cred_type
                        values["Domain"] = domain
                        # Extract basic authentication if we are on a "http-basic" section
                        # otherwise extract authentication token
                        if cred_type == "http-basic":
                            values["Login"] = creds[cred_type][domain]["username"]
                            values["Password"] = creds[cred_type][domain]["password"]
                        else:
                            values["Password"] = creds[cred_type][domain]
                        creds_found.append(values)

        return creds_found

    def run(self, software_name=None):
        """
        Main function
        """

        # Define the possible full path of the "auth.json" file when is defined at global level
        # See "https://getcomposer.org/doc/articles/http-basic-authentication.md"
        # See "https://seld.be/notes/authentication-management-in-composer"
        if "COMPOSER_HOME" in os.environ:
            location = os.environ.get("COMPOSER_HOME") + "\\auth.json"
        else:
            location = os.environ.get("APPDATA") + "\\Composer\\auth.json"

        # Extract the credentials
        creds_found = self.extract_credentials(location)

        return creds_found
