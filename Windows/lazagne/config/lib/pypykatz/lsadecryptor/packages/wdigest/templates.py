#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
import struct

from ....commons.common import KatzSystemArchitecture, WindowsMinBuild
from ....commons.win_datatypes import POINTER, ULONG, LUID, LSA_UNICODE_STRING
from ...package_commons import PackageTemplate


class WdigestTemplate(PackageTemplate):
    def __init__(self):
        super(WdigestTemplate, self).__init__('Wdigest')
        self.signature = None
        self.first_entry_offset = None
        self.list_entry = None

    @staticmethod
    def get_template(sysinfo):
        template = WdigestTemplate()
        template.list_entry = PWdigestListEntry
        template.log_template('list_entry', template.list_entry)
        if sysinfo.architecture == KatzSystemArchitecture.X64:
            if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
                template.signature = b'\x48\x3b\xda\x74'
                template.first_entry_offset = -4

            elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
                template.signature = b'\x48\x3b\xda\x74'
                template.first_entry_offset = -4
            elif sysinfo.buildnumber >= WindowsMinBuild.WIN_VISTA.value:
                template.signature = b'\x48\x3b\xd9\x74'
                template.first_entry_offset = -4

            else:
                raise Exception('Could not identify template! Architecture: %s sysinfo.buildnumber: %s' %
                                (sysinfo.architecture, sysinfo.buildnumber))

        elif sysinfo.architecture == KatzSystemArchitecture.X86:
            if WindowsMinBuild.WIN_XP.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_2K3.value:
                template.signature = b'\x74\x18\x8b\x4d\x08\x8b\x11'
                template.first_entry_offset = -6
            elif WindowsMinBuild.WIN_2K3.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
                template.signature = b'\x74\x18\x8b\x4d\x08\x8b\x11'
                template.first_entry_offset = -6

            elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
                template.signature = b'\x74\x11\x8b\x0b\x39\x4e\x10'
                template.first_entry_offset = -6

            elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_10.value:
                template.signature = b'\x74\x15\x8b\x0a\x39\x4e\x10'
                template.first_entry_offset = -4

            elif sysinfo.buildnumber >= WindowsMinBuild.WIN_10.value:
                template.signature = b'\x74\x15\x8b\x0a\x39\x4e\x10'
                template.first_entry_offset = -6

            else:
                template.signature = b'\x74\x15\x8b\x17\x39\x56\x10'
                template.first_entry_offset = -6

        else:
            raise Exception('Unknown architecture! %s' % sysinfo.architecture)

        return template


class PWdigestListEntry(POINTER):
    def __init__(self, reader):
        super(PWdigestListEntry, self).__init__(reader, WdigestListEntry)


class WdigestListEntry:
    def __init__(self, reader):
        self.Flink = PWdigestListEntry(reader)
        self.Blink = PWdigestListEntry(reader)
        self.usage_count = ULONG(reader)
        reader.align()
        self.this_entry = PWdigestListEntry(reader)
        self.luid = LUID(reader).value
        self.flag = struct.unpack("<Q", reader.read(8))[0]
        self.UserName = LSA_UNICODE_STRING(reader)
        self.DomainName = LSA_UNICODE_STRING(reader)
        self.Password = LSA_UNICODE_STRING(reader)
