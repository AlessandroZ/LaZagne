# -*- coding: utf-8 -*- 
from creddump7.win32.hashdump import dump_file_hashes
from lazagne.config.write_output import print_debug
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import *
from lazagne.config.constant import *
import tempfile
import random
import string
import os

class Hashdump(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'hashdump', 'windows', system_module=True)

	def run(self, software_name=None):
		hashdump = dump_file_hashes(constant.hives['system'], constant.hives['sam'])
		if hashdump: 
			pwdFound = ['__Hashdump__', hashdump]
			return pwdFound
