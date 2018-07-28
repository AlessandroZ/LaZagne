# -*- coding: utf-8 -*-
import os

from lazagne.config.module_info import ModuleInfo
from lazagne.softwares.browsers.chromium_based import ChromiumBased


class UCBrowser(ChromiumBased):
	def __init__(self):
		data_dir = '{}\\UCBrowser'.format(os.getenv("LOCALAPPDATA"))
		try:
			# UC Browser seems to have random characters appended to the User Data dir so we'll list them all
			self.paths = [os.path.join(data_dir, d) for d in os.listdir(data_dir)]
		except Exception:
			self.paths = []
		self.database_query = 'SELECT action_url, username_value, password_value FROM wow_logins'
		ModuleInfo.__init__(self, 'UC Browser', 'browsers', dpapi_used=True)
