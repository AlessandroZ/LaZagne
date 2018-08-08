#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Code based from these two awesome projects: 
- DPAPICK 	: https://bitbucket.org/jmichel/dpapick
- DPAPILAB 	: https://github.com/dfirfpi/dpapilab
"""

from .structures import *


class CredSystem():
    """
    This represents the DPAPI_SYSTEM token which is stored as an LSA secret.

    Sets 2 properties:
        self.machine
        self.user
    """

    def __init__(self, dpapi_system):
        cred_system = CRED_SYSTEM.parse(dpapi_system)
        self.revision = cred_system.revision
        self.machine = cred_system.machine
        self.user = cred_system.user
