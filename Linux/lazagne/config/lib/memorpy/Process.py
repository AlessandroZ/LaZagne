#!/usr/bin/env python
# -*- coding: UTF8 -*-

import sys
from .BaseProcess import *
if sys.platform=='win32':
    from .WinProcess import WinProcess as Process
elif sys.platform=='darwin':
    from .OSXProcess import OSXProcess as Process
elif 'sunos' in sys.platform:
    from .SunProcess import SunProcess as Process
else:
    from .LinProcess import LinProcess as Process
