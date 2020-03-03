#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
import json

from ...package_commons import PackageDecryptor


class LiveSspCredential:
    def __init__(self):
        self.credtype = 'livessp'
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
        t = '\t== LiveSsp [%x]==\n' % self.luid
        t += '\tusername %s\n' % self.username
        t += '\tdomainname %s\n' % self.domainname
        t += '\tpassword %s\n' % self.password
        return t


class LiveSspDecryptor(PackageDecryptor):
    def __init__(self, reader, decryptor_template, lsa_decryptor, sysinfo):
        super(LiveSspDecryptor, self).__init__(
            'LiveSsp', lsa_decryptor, sysinfo, reader)
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
        c = LiveSspCredential()
        c.luid = ssp_entry.LocallyUniqueIdentifier
        suppCreds = ssp_entry.suppCreds.read(self.reader)

        c.username = suppCreds.credentials.UserName.read_string(self.reader)
        c.domainname = suppCreds.credentials.Domaine.read_string(self.reader)
        if suppCreds.credentials.Password.Length != 0:
            enc_data = suppCreds.credentials.Password.read_maxdata(self.reader)
            c.password = self.decrypt_password(enc_data)

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
