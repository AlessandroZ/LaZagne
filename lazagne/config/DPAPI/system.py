#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from .eater import DataStruct


class CredSystem(DataStruct):
    """
    This represents the DPAPI_SYSTEM token which is stored as an LSA secret.

    Sets 2 properties:
        self.machine
        self.user
    """

    def __init__(self, raw=None):
        self.revision = None
        self.machine = None
        self.user = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        """Parses the given data. May raise exceptions if incorrect data are
            given. You should not call this function yourself; DataStruct does

            data is a DataStruct object.
            Returns nothing.

        """
        self.revision = data.eat("L")
        self.machine = data.eat("20s")
        self.user = data.eat("20s")
