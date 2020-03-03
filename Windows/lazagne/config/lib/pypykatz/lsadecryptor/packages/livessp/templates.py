#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
from ...package_commons import PackageTemplate
from ....commons.common import KatzSystemArchitecture
from ....commons.win_datatypes import POINTER, ULONG, PVOID, DWORD, LUID, LSA_UNICODE_STRING, \
    KIWI_GENERIC_PRIMARY_CREDENTIAL


class LiveSspTemplate(PackageTemplate):
    def __init__(self):
        super(LiveSspTemplate, self).__init__('LiveSsp')
        self.signature = None
        self.first_entry_offset = None
        self.list_entry = None

    @staticmethod
    def get_template(sysinfo):
        template = LiveSspTemplate()
        template.list_entry = PKIWI_LIVESSP_LIST_ENTRY
        template.log_template('list_entry', template.list_entry)

        if sysinfo.architecture == KatzSystemArchitecture.X64:
            template.signature = b'\x74\x25\x8b'
            template.first_entry_offset = -7

        elif sysinfo.architecture == KatzSystemArchitecture.X86:
            template.signature = b'\x8b\x16\x39\x51\x24\x75\x08'
            template.first_entry_offset = -8

        else:
            raise Exception('Unknown architecture! %s' % sysinfo.architecture)

        return template


class PKIWI_LIVESSP_PRIMARY_CREDENTIAL(POINTER):
    def __init__(self, reader):
        super(PKIWI_LIVESSP_PRIMARY_CREDENTIAL, self).__init__(
            reader, KIWI_LIVESSP_PRIMARY_CREDENTIAL)


class KIWI_LIVESSP_PRIMARY_CREDENTIAL:
    def __init__(self, reader):
        self.isSupp = ULONG(reader).value
        self.unk0 = ULONG(reader).value
        self.credentials = KIWI_GENERIC_PRIMARY_CREDENTIAL(reader)


class PKIWI_LIVESSP_LIST_ENTRY(POINTER):
    def __init__(self, reader):
        super(PKIWI_LIVESSP_LIST_ENTRY, self).__init__(
            reader, KIWI_LIVESSP_LIST_ENTRY)


class KIWI_LIVESSP_LIST_ENTRY:
    def __init__(self, reader):
        self.Flink = PKIWI_LIVESSP_LIST_ENTRY(reader)
        self.Blink = PKIWI_LIVESSP_LIST_ENTRY(reader)
        self.unk0 = PVOID(reader)
        self.unk1 = PVOID(reader)
        self.unk2 = PVOID(reader)
        self.unk3 = PVOID(reader)
        self.unk4 = DWORD(reader).value
        self.unk5 = DWORD(reader).value
        self.unk6 = PVOID(reader)
        self.LocallyUniqueIdentifier = LUID(reader).value
        self.UserName = LSA_UNICODE_STRING(reader)
        self.unk7 = PVOID(reader)
        self.suppCreds = PKIWI_LIVESSP_PRIMARY_CREDENTIAL(reader)
