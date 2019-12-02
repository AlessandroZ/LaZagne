# -*- coding: utf-8 -*- 
import os

try: 
    from urlparse import urlparse
except ImportError: 
    from urllib.parse import urlparse

from lazagne.config.module_info import ModuleInfo


class GitForLinux(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'gitforlinux', 'git')

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
                # One line have the following format: https://user:pass@example.com
                for cred in f:
                    if len(cred) > 0:
                        parts = urlparse(cred)
                        pwd_found.append((
                            parts.geturl().replace(parts.username + ":" + parts.password + "@", "").strip(),
                            parts.username,
                            parts.password
                        ))

        return pwd_found

    def run(self):
        """
        Main function
        """

        # According to the "git-credential-store" documentation:
        # Build a list of locations in which git credentials can be stored
        locations = [
            os.path.join(os.path.expanduser("~"), '.git-credentials'),
            os.path.join(os.path.expanduser("~"), '.config/git/credentials'),
        ]
        if "XDG_CONFIG_HOME" in os.environ:
            locations.append(os.path.join(os.environ.get('XDG_CONFIG_HOME'), 'git/credentials'))

        # Apply the password extraction on the defined locations
        pwd_found = []
        for location in locations:
            pwd_found += self.extract_credentials(location)

        # Filter duplicates
        return [{'URL': url, 'Login': login, 'Password': password} for url, login, password in set(pwd_found)]
