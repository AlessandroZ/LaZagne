#!/usr/bin/env python
# -*- coding: UTF8 -*-

import sys
if sys.platform=="win32":
    from .WinStructures import *
else:
    from .LinStructures import *
