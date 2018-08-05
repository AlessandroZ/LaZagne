# -*- coding: utf-8 -*- 
from creddump7.win32.domcachedump import dump_file_hashes
from lazagne.config.write_output import print_debug
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import *
from lazagne.config.constant import *
import tempfile
import random
import string
import os

class Cachedump(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'mscache', 'windows', system_module=True)

	def run(self, software_name=None):
		isVistaOrHigher = False
		if float(get_os_version()) >= 6.0:
			isVistaOrHigher = True
		
		mscache = dump_file_hashes(constant.hives['system'], constant.hives['security'], isVistaOrHigher)
		if mscache:
			pwdFound = ['__MSCache__', mscache]
			return pwdFound
