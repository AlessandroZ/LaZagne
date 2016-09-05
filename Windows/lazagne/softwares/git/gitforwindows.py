import os
from lazagne.config.write_output import print_debug
from lazagne.config.constant import *
from lazagne.config.moduleInfo import ModuleInfo
from urlparse import urlparse

class GitForWindows(ModuleInfo):

    def __init__(self):
        options = {'command': '-t', 'action': 'store_true', 'dest': 'gitforwindows', 'help': 'Git for Windows'}
        ModuleInfo.__init__(self, 'gitforwindows', 'git', options)

    def extract_credentials(self, location):
        """
        Extract the credentials from a Git store file.
        See "https://git-scm.com/docs/git-credential-store" for file format.
        :param location: Full path to the Git store file
        :return: List of credentials founds
        """
        pwd_found = []
        values = {}
        if os.path.isfile(location):
            with open(location) as f:
                creds = f.readlines()
                # One line have the following format: https://user:pass@example.com
                for cred in creds:
                    if len(cred) > 0:
                        parts = urlparse(cred)
                        values["Username"] = parts.username
                        values["Password"] = parts.password
                        values["URL"] = parts.geturl().replace(parts.username + ":" + parts.password + "@", "").strip()
                        pwd_found.append(values)

        return pwd_found

    def run(self, software_name = None):
        """
        Main function
        """
       
        # According to the "git-credential-store" documentation:
        # Build a list of locations in which git credentials can be stored
        locations = []
        locations.append(os.environ.get("USERPROFILE") + "\\.git-credentials")
        locations.append(os.environ.get("USERPROFILE") + "\\.config\\git\\credentials")
        if "XDG_CONFIG_HOME" in os.environ:
            locations.append(os.environ.get("XDG_CONFIG_HOME") + "\\git\\credentials")

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
