# -*- coding: utf-8 -*- 
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config.constant import *
from urlparse import urlparse
import os

class GitForWindows(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, 'gitforwindows', 'git')

    def extract_credentials(self, location):
        """
        Extract the credentials from a Git store file.
        See "https://git-scm.com/docs/git-credential-store" for file format.
        :param location: Full path to the Git store file
        :return: List of credentials founds
        """
        pwd_found = []
        if os.path.isfile(location):
            with open(location) as f:
                creds = f.readlines()
                # One line have the following format: https://user:pass@example.com
                for cred in creds:
                    if len(cred) > 0:
                        parts = urlparse(cred)
                        pwd_found.append(
                            {
                                'Login'     :   parts.username, 
                                'Password'  :   parts.password, 
                                'URL'       :   parts.geturl().replace(parts.username + ":" + parts.password + "@", "").strip()
                            }
                        )

        return pwd_found

    def run(self, software_name=None):
        """
        Main function
        """
       
        # According to the "git-credential-store" documentation:
        # Build a list of locations in which git credentials can be stored
        locations = [
            os.path.join(constant.profile["USERPROFILE"], u'\\.git-credentials'), 
            os.path.join(constant.profile["USERPROFILE"], u'\\.config\\git\\credentials'),
        ]
        if "XDG_CONFIG_HOME" in os.environ:
            locations.append(unicode(os.environ.get('XDG_CONFIG_HOME')) + u'\\git\\credentials')

        # Apply the password extraction on the defined locations
        pwd_found = []
        for location in locations:
            pwd_found += self.extract_credentials(location)

        # Filter duplicates
        final_pwd_found = []
        duplicates_track = []
        for pwd in pwd_found:
            pwd_id = pwd["URL"] + pwd["Username"] + pwd["Password"]
            if pwd_id not in duplicates_track:
                final_pwd_found.append(pwd)
                duplicates_track.append(pwd_id)

        return final_pwd_found
