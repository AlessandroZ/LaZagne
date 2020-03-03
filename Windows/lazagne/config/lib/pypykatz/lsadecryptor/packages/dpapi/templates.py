#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#

from ...package_commons import PackageTemplate
from ....commons.common import KatzSystemArchitecture, WindowsBuild, WindowsMinBuild
from ....commons.win_datatypes import POINTER, LUID, GUID, FILETIME, ULONG


class DpapiTemplate(PackageTemplate):
    def __init__(self):
        super(DpapiTemplate, self).__init__('Dpapi')
        self.signature = None
        self.first_entry_offset = None
        self.list_entry = None

    @staticmethod
    def get_template(sysinfo):
        template = DpapiTemplate()
        template.list_entry = PKIWI_MASTERKEY_CACHE_ENTRY
        template.log_template('list_entry', template.list_entry)

        if sysinfo.architecture == KatzSystemArchitecture.X64:
            if sysinfo.buildnumber < WindowsMinBuild.WIN_VISTA.value:
                template.signature = b'\x4d\x3b\xee\x49\x8b\xfd\x0f\x85'
                template.first_entry_offset = -4

            elif WindowsMinBuild.WIN_VISTA.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_7.value:
                template.signature = b'\x49\x3b\xef\x48\x8b\xfd\x0f\x84'
                template.first_entry_offset = -4

            elif WindowsMinBuild.WIN_7.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
                template.signature = b'\x33\xc0\xeb\x20\x48\x8d\x05'
                template.first_entry_offset = 7

            elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
                template.signature = b'\x4c\x89\x1f\x48\x89\x47\x08\x49\x39\x43\x08\x0f\x85'
                template.first_entry_offset = -4

            elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1507.value:
                template.signature = b'\x08\x48\x39\x48\x08\x0f\x85'
                template.first_entry_offset = -10

            elif WindowsBuild.WIN_10_1507.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
                template.signature = b'\x48\x89\x4e\x08\x48\x39\x48\x08'
                template.first_entry_offset = -7

            elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1607.value:
                template.signature = b'\x48\x89\x4f\x08\x48\x89\x78\x08'
                template.first_entry_offset = 11

            else:
                # currently this doesnt make sense, but keeping it here for future use
                raise Exception('Could not identify template! Architecture: %s sysinfo.buildnumber: %s' % (
                    sysinfo.architecture, sysinfo.buildnumber))

        elif sysinfo.architecture == KatzSystemArchitecture.X86:
            if sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
                template.signature = b'\x33\xc0\x40\xa3'
                template.first_entry_offset = -4

            elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
                template.signature = b'\x8b\xf0\x81\xfe\xcc\x06\x00\x00\x0f\x84'
                template.first_entry_offset = -16

            elif sysinfo.buildnumber >= WindowsMinBuild.WIN_BLUE.value:
                template.signature = b'\x33\xc0\x40\xa3'
                template.first_entry_offset = -4

        else:
            raise Exception('Unknown architecture! %s' % sysinfo.architecture)

        return template


class PKIWI_MASTERKEY_CACHE_ENTRY(POINTER):
    def __init__(self, reader):
        super(PKIWI_MASTERKEY_CACHE_ENTRY, self).__init__(
            reader, KIWI_MASTERKEY_CACHE_ENTRY)


class KIWI_MASTERKEY_CACHE_ENTRY:
    def __init__(self, reader):
        self.Flink = PKIWI_MASTERKEY_CACHE_ENTRY(reader)
        self.Blink = PKIWI_MASTERKEY_CACHE_ENTRY(reader)
        self.LogonId = LUID(reader).value
        self.KeyUid = GUID(reader).value
        self.insertTime = FILETIME(reader)
        self.keySize = ULONG(reader).value
        self.key = reader.read(self.keySize)
