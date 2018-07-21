# -*- coding: utf-8 -*- 
import json
import os
import shutil
import sqlite3
import tempfile
import traceback

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config.winstructure import Win32CryptUnprotectData
from lazagne.config.write_output import print_debug


class ChromiumBased(ModuleInfo):
	def __init__(self, browser_name, paths):
		self.paths = paths if isinstance(paths, list) else [paths]
		ModuleInfo.__init__(self, browser_name, 'browsers', dpapi_used=True)

	def _get_database_dirs(self):
		"""
		Return database directories for all profiles within all paths
		"""
		databases = set()
		for path in [p.format(**constant.profile) for p in self.paths]:
			profiles_path = os.path.join(path, u'Local State')
			if os.path.exists(profiles_path):
				# List all users profile (empty string means current dir, without a profile)
				profiles = {'Default', ''}
				with open(profiles_path) as f:
					try:
						data = json.load(f)
						# Add profiles from json to Default profile. set removes duplicates
						profiles |= set(data['profile']['info_cache'])
					except Exception:
						pass
				# Each profile has its own password database
				for profile in profiles:
					database_path = os.path.join(path, profile, u'Login Data')
					if os.path.exists(database_path):
						databases.add(database_path)
		return databases

	@staticmethod
	def _export_credentials(db_path):
		"""
		Export credentials from the given database

		:param unicode db_path: database path
		:return: list of credentials
		:rtype: tuple
		"""

		credentials = []

		try:
			conn = sqlite3.connect(db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT action_url, username_value, password_value FROM logins')
		except Exception, e:
			print_debug('DEBUG', str(e))
			print_debug('ERROR', u'An error occurred while opening the database file')
			return credentials

		for url, login, password in cursor.fetchall():
			try:
				# Decrypt the Password
				password = Win32CryptUnprotectData(password)
				credentials.append((url, login, password))
			except Exception:
				print_debug('DEBUG', traceback.format_exc())

		conn.close()
		return credentials

	def run(self, software_name=None):
		credentials = []
		for database_path in self._get_database_dirs():
			# Copy database before to query it (bypass lock errors)
			try:
				temp = unicode(os.path.join(tempfile.gettempdir(), next(tempfile._get_candidate_names())))
				shutil.copy(database_path, temp)
				credentials.extend(self._export_credentials(temp))
			except Exception:
				print_debug('DEBUG', traceback.format_exc())

		return [{"URL": url, "Login": login, "Password": password} for url, login, password in set(credentials)]


# Name, path or a list of paths
chromium_browsers = [
	('7Star', '{LOCALAPPDATA}\\7Star\\7Star\\User Data'),
	('Amigo', '{LOCALAPPDATA}\\Amigo\\User\\User Data'),
	('Brave', '{APPDATA}\\brave'),
	('CentBrowser', '{LOCALAPPDATA}\\CentBrowser\\User Data'),
	('Chedot', '{LOCALAPPDATA}\\Chedot\\User Data'),
	('Chrome Canary', '{LOCALAPPDATA}\\Google\\Chrome SxS\\User Data'),
	('Chromium', '{LOCALAPPDATA}\\Chromium\\User Data'),
	('CocCoc', '{LOCALAPPDATA}\\CocCoc\\Browser\\User Data'),
	('Comodo Dragon', '{LOCALAPPDATA}\\Comodo\\Dragon\\User Data'),  # Comodo IceDragon is Firefox-based
	('Google Chrome', '{LOCALAPPDATA}\\Google\\Chrome\\User Data'),
	('Kometa', '{LOCALAPPDATA}\\Kometa\\User Data'),
	('Opera', '{APPDATA}\\Opera Software\\Opera Stable'),
	('Orbitum', '{LOCALAPPDATA}\\Orbitum\\User Data'),
	('Torch', '{LOCALAPPDATA}\\Torch\\User Data'),
	('Vivaldi', '{LOCALAPPDATA}\\Vivaldi\\User Data'),
	('YandexBrowser', '{LOCALAPPDATA}\\Yandex\\YandexBrowser\\User Data')
]

chromium_browsers = [ChromiumBased(browser_name=name, paths=paths) for name, paths in chromium_browsers]
