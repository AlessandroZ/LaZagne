#!/usr/bin/env python
#
# Author:
#  Tamas Jos (@skelsec)
#
from ....commons.common import KatzSystemArchitecture, WindowsBuild, WindowsMinBuild
from ....commons.win_datatypes import POINTER, PVOID, LUID, KIWI_GENERIC_PRIMARY_CREDENTIAL
from ...package_commons import PackageTemplate


class TspkgTemplate(PackageTemplate):
    def __init__(self):
        super(TspkgTemplate, self).__init__('Tspkg')
        self.signature = None
        self.avl_offset = None
        self.credential_struct = None

    @staticmethod
    def get_template(sysinfo):
        template = TspkgTemplate()
        if sysinfo.architecture == KatzSystemArchitecture.X64:
            template.signature = b'\x48\x83\xec\x20\x48\x8d\x0d'
            template.avl_offset = 7

            if sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
                template.credential_struct = KIWI_TS_CREDENTIAL_x64

            elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1607.value:
                template.credential_struct = KIWI_TS_CREDENTIAL_1607_x64

            else:
                # currently this doesnt make sense, but keeping it here for future use
                raise Exception('Could not identify template! Architecture: %s Buildnumber: %s' % (
                    sysinfo.architecture, sysinfo.buildnumber))

        elif sysinfo.architecture == KatzSystemArchitecture.X86:
            if sysinfo.buildnumber < WindowsMinBuild.WIN_8.value:
                template.signature = b'\x8b\xff\x55\x8b\xec\x51\x56\xbe'
                template.avl_offset = 8
                template.credential_struct = KIWI_TS_CREDENTIAL

            elif WindowsMinBuild.WIN_8.value <= sysinfo.buildnumber < WindowsMinBuild.WIN_BLUE.value:
                template.signature = b'\x8b\xff\x53\xbb'
                template.avl_offset = 4
                template.credential_struct = KIWI_TS_CREDENTIAL

            elif WindowsMinBuild.WIN_BLUE.value <= sysinfo.buildnumber < WindowsBuild.WIN_10_1607.value:
                template.signature = b'\x8b\xff\x57\xbf'
                template.avl_offset = 4
                template.credential_struct = KIWI_TS_CREDENTIAL

            elif sysinfo.buildnumber >= WindowsBuild.WIN_10_1607.value:
                template.signature = b'\x8b\xff\x57\xbf'
                template.avl_offset = 4
                template.credential_struct = KIWI_TS_CREDENTIAL_1607

        else:
            raise Exception('Unknown architecture! %s' % sysinfo.architecture)

        template.log_template('credential_struct', template.credential_struct)

        return template


class PKIWI_TS_PRIMARY_CREDENTIAL(POINTER):
    def __init__(self, reader):
        super(PKIWI_TS_PRIMARY_CREDENTIAL, self).__init__(
            reader, KIWI_TS_PRIMARY_CREDENTIAL)


class KIWI_TS_PRIMARY_CREDENTIAL:
    def __init__(self, reader):
        self.unk0 = PVOID(reader)  # // lock ?
        self.credentials = KIWI_GENERIC_PRIMARY_CREDENTIAL(reader)


class KIWI_TS_CREDENTIAL:
    def __init__(self, reader):
        self.unk0 = reader.read(64)
        self.LocallyUniqueIdentifier = LUID(reader).value
        reader.align()
        self.unk1 = PVOID(reader)
        self.unk2 = PVOID(reader)
        self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)


class KIWI_TS_CREDENTIAL_x64:
    def __init__(self, reader):
        self.unk0 = reader.read(108)
        self.LocallyUniqueIdentifier = LUID(reader).value
        reader.align()
        self.unk1 = PVOID(reader)
        self.unk2 = PVOID(reader)
        self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)


class KIWI_TS_CREDENTIAL_1607:
    def __init__(self, reader):
        self.unk0 = reader.read(68)
        self.LocallyUniqueIdentifier = LUID(reader).value
        reader.align()
        self.unk1 = PVOID(reader)
        self.unk2 = PVOID(reader)
        self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)


class KIWI_TS_CREDENTIAL_1607_x64:
    def __init__(self, reader):
        self.unk0 = reader.read(112)
        self.LocallyUniqueIdentifier = LUID(reader).value
        reader.align()
        self.unk1 = PVOID(reader)
        self.unk2 = PVOID(reader)
        self.pTsPrimary = PKIWI_TS_PRIMARY_CREDENTIAL(reader)
