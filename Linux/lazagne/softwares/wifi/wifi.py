#!/usr/bin/env python
# -*- coding: utf-8 -*- 
from ConfigParser import RawConfigParser
from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
import os

class Wifi(ModuleInfo):
	def __init__(self):
		ModuleInfo.__init__(self, 'wifi', 'wifi')

	def run(self, software_name=None):
		pwdFound 	= []
		directory 	= u'/etc/NetworkManager/system-connections'

		if os.path.exists(directory):
			if os.getuid() == 0:
				wireless_ssid = [ f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory,f))]
				
				for w in wireless_ssid:
					cp = RawConfigParser()
					cp.read(os.path.join(directory, w))
					values = {'SSID': w}
					try:
						values['Password'] = cp.get('wifi-security', 'psk')
						pwdFound.append(values)
					except:
						pass
				
				return pwdFound