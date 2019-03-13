# -*- coding: utf-8 -*- 
import json

from lazagne.config.module_info import ModuleInfo
from lazagne.config.constant import constant

import os


class Composer(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'composer', 'php')

    def extract_credentials(self, location):
        """
        Extract the credentials from the "auth.json" file.
        See "https://getcomposer.org/doc/articles/http-basic-authentication.md" for file format.
        :param location: Full path to the "auth.json" file
        :return: List of credentials founds
        """
        creds_found = []
        with open(location) as f:
            creds = json.load(f)
            for cred_type in creds:
                for domain in creds[cred_type]:
                    values = {
                        "AuthenticationType" : cred_type,
                        "Domain" : domain,
                    }
                    # Extract basic authentication if we are on a "http-basic" section
                    # otherwise extract authentication token
                    if cred_type == "http-basic":
                        values["Login"] = creds[cred_type][domain]["username"]
                        values["Password"] = creds[cred_type][domain]["password"]
                    else:
                        values["Password"] = creds[cred_type][domain]
                    creds_found.append(values)

        return creds_found

    def run(self):
        """
        Main function
        """

        # Define the possible full path of the "auth.json" file when is defined at global level
        # See "https://getcomposer.org/doc/articles/http-basic-authentication.md"
        # See "https://seld.be/notes/authentication-management-in-composer"
        location = ''
        tmp_location = [
            os.path.join(constant.profile["COMPOSER_HOME"], u'auth.json'), 
            os.path.join(constant.profile["APPDATA"], u'Composer\\auth.json')
        ]
        for tmp in tmp_location:
            if os.path.isfile(tmp):
                location = tmp
                break
            
        if location:
            return self.extract_credentials(location)
