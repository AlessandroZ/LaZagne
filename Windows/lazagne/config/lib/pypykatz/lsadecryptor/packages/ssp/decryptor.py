#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
import json

from ...package_commons import PackageDecryptor


class SspCredential:
    def __init__(self):
        self.credtype = 'ssp'
        self.username = None
        self.domainname = None
        self.password = None
        self.luid = None

    def to_dict(self):
        return {
            'credtype': self.credtype,
            'username': self.username,
            'domainname': self.domainname,
            'password': self.password,
            'luid': self.luid
        }

    def to_json(self):
        return json.dumps(self.to_dict())

    def __str__(self):
        t = '\t== SSP [%x]==\n' % self.luid
        t += '\t\tusername %s\n' % self.username
        t += '\t\tdomainname %s\n' % self.domainname
        t += '\t\tpassword %s\n' % self.password
        return t


class SspDecryptor(PackageDecryptor):
    def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
        super(SspDecryptor, self).__init__(
            'Ssp', lsa_decryptor, sysinfo, reader)
        self.decryptor_template = decryptor_template
        self.credentials = []

    def find_first_entry(self):
        position = self.find_signature(
            'msv1_0.dll', self.decryptor_template.signature)
        ptr_entry_loc = self.reader.get_ptr_with_offset(
            position + self.decryptor_template.first_entry_offset)
        ptr_entry = self.reader.get_ptr(ptr_entry_loc)
        return ptr_entry, ptr_entry_loc

    def add_entry(self, ssp_entry):
        c = SspCredential()
        c.luid = ssp_entry.LogonId
        c.username = ssp_entry.credentials.UserName.read_string(self.reader)
        c.domainname = ssp_entry.credentials.Domaine.read_string(self.reader)
        if ssp_entry.credentials.Password.Length != 0:
            c.password = self.decrypt_password(
                ssp_entry.credentials.Password.read_maxdata(self.reader))

        self.credentials.append(c)

    def start(self):
        try:
            entry_ptr_value, entry_ptr_loc = self.find_first_entry()
        except Exception as e:
            self.log('Failed to find structs! Reason: %s' % e)
            return
        self.reader.move(entry_ptr_loc)
        entry_ptr = self.decryptor_template.list_entry(self.reader)
        self.walk_list(entry_ptr, self.add_entry)
