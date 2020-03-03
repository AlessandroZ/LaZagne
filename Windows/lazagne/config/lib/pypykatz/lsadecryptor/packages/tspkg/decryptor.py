#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#

import json

from ...package_commons import PackageDecryptor
from ....commons.win_datatypes import PRTL_AVL_TABLE


class TspkgCredential:
    def __init__(self):
        self.credtype = 'tspkg'
        self.username = None
        self.domainname = None
        self.password = None
        self.luid = None

    def to_dict(self):
        t = {}
        t['credtype'] = self.credtype
        t['username'] = self.username
        t['domainname'] = self.domainname
        t['password'] = self.password
        t['luid'] = self.luid
        return t

    def to_json(self):
        return json.dumps(self.to_dict())

    def __str__(self):
        t = '\t== TSPKG [%x]==\n' % self.luid
        t += '\t\tusername %s\n' % self.username
        t += '\t\tdomainname %s\n' % self.domainname
        t += '\t\tpassword %s\n' % self.password
        return t


class TspkgDecryptor(PackageDecryptor):
    def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
        super(TspkgDecryptor, self).__init__(
            'Tspkg', lsa_decryptor, sysinfo, reader)
        self.decryptor_template = decryptor_template
        self.credentials = []

    def find_first_entry(self):
        position = self.find_signature(
            'TSpkg.dll', self.decryptor_template.signature)
        ptr_entry_loc = self.reader.get_ptr_with_offset(
            position + self.decryptor_template.avl_offset)
        ptr_entry = self.reader.get_ptr(ptr_entry_loc)
        return ptr_entry, ptr_entry_loc

    def start(self):
        try:
            entry_ptr_value, entry_ptr_loc = self.find_first_entry()
        except Exception as e:
            self.log('Failed to find structs! Reason: %s' % e)
            return
        result_ptr_list = []
        self.reader.move(entry_ptr_value)
        start_node = PRTL_AVL_TABLE(self.reader).read(self.reader)
        self.walk_avl(start_node.BalancedRoot.RightChild, result_ptr_list)
        for ptr in result_ptr_list:
            self.log_ptr(
                ptr, self.decryptor_template.credential_struct.__name__)
            self.reader.move(ptr)
            credential_struct = self.decryptor_template.credential_struct(
                self.reader)
            primary_credential = credential_struct.pTsPrimary.read(self.reader)
            if not primary_credential is None:
                c = TspkgCredential()
                c.luid = credential_struct.LocallyUniqueIdentifier
                c.username = primary_credential.credentials.UserName.read_string(
                    self.reader)
                c.domainname = primary_credential.credentials.Domaine.read_string(
                    self.reader)
                if primary_credential.credentials.Password.Length != 0:
                    enc_data = primary_credential.credentials.Password.read_maxdata(
                        self.reader)
                    c.password = self.decrypt_password(enc_data)

                self.credentials.append(c)
