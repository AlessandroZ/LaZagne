# -*- coding: utf-8 -*- 
import os

try: 
    from urlparse import urlparse, unquote
except ImportError: 
    from urllib.parse import urlparse, unquote

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import string_to_unicode


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
                # One line have the following format: https://user:pass@example.com
                for cred in f:
                    if len(cred) > 0:
                        parts = urlparse(cred)
                        pwd_found.append((
                            unquote(parts.geturl().replace(parts.username + ":" + parts.password + "@", "").strip()),
                            unquote(parts.username),
                            unquote(parts.password)
                        ))

        return pwd_found

    def run(self):
        """
        Main function
        """

        # According to the "git-credential-store" documentation:
        # Build a list of locations in which git credentials can be stored
        locations = [
            os.path.join(constant.profile["USERPROFILE"], u'.git-credentials'),
            os.path.join(constant.profile["USERPROFILE"], u'.config\\git\\credentials'),
        ]
        if "XDG_CONFIG_HOME" in os.environ:
            locations.append(os.path.join(string_to_unicode(os.environ.get('XDG_CONFIG_HOME')), u'git\\credentials'))

        # Apply the password extraction on the defined locations
        pwd_found = []
        for location in locations:
            pwd_found += self.extract_credentials(location)

        # Filter duplicates
        return [{'URL': url, 'Login': login, 'Password': password} for url, login, password in set(pwd_found)]
