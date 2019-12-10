# -*- coding: utf-8 -*-
import os
import psutil

try: 
    from urlparse import urlparse, unquote
except ImportError: 
    from urllib.parse import urlparse, unquote

from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes


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
                            unquote(parts.geturl().replace(parts.username + ":" + parts.password + "@", "").strip()),
                            unquote(parts.username),
                            unquote(parts.password)
                        ))

        return pwd_found

    def run(self):
        """
        Main function
        """
        known_locations = set()

        # According to the "git-credential-store" documentation:
        # Build a list of locations in which git credentials can be stored

        # Apply the password extraction on the defined locations
        pwd_found = []
        for location in homes.get(file=[u'.git-credentials', u'.config/git/credentials']):
            pwd_found += self.extract_credentials(location)
            known_locations.add(location)

        # Read Env variable from another user
        for process in psutil.process_iter():
            try:
                environ = process.environ()
            except Exception:
                continue

            for var in ('XDG_CONFIG_HOME', ):
                if var not in environ or environ[var] in known_locations:
                        continue

                # Env variable found
                location = environ[var]
                known_locations.add(location)
                pwd_found += self.extract_credentials(os.path.join(location, 'git/credentials'))

        # Filter duplicates
        return [{'URL': url, 'Login': login, 'Password': password} for url, login, password in set(pwd_found)]
