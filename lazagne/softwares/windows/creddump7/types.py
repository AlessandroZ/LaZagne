# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

regtypes = {
    '_CM_KEY_VALUE': [0x18, {
        'Signature': [0x0, ['unsigned short']],
        'NameLength': [0x2, ['unsigned short']],
        'DataLength': [0x4, ['unsigned long']],
        'Data': [0x8, ['unsigned long']],
        'Type': [0xc, ['unsigned long']],
        'Flags': [0x10, ['unsigned short']],
        'Spare': [0x12, ['unsigned short']],
        'Name': [0x14, ['array', 1, ['unsigned short']]],
    }],
    '_CM_KEY_NODE': [0x50, {
        'Signature': [0x0, ['unsigned short']],
        'Flags': [0x2, ['unsigned short']],
        'LastWriteTime': [0x4, ['_LARGE_INTEGER']],
        'Spare': [0xc, ['unsigned long']],
        'Parent': [0x10, ['unsigned long']],
        'SubKeyCounts': [0x14, ['array', 2, ['unsigned long']]],
        'SubKeyLists': [0x1c, ['array', 2, ['unsigned long']]],
        'ValueList': [0x24, ['_CHILD_LIST']],
        'ChildHiveReference': [0x1c, ['_CM_KEY_REFERENCE']],
        'Security': [0x2c, ['unsigned long']],
        'Class': [0x30, ['unsigned long']],
        'MaxNameLen': [0x34, ['unsigned long']],
        'MaxClassLen': [0x38, ['unsigned long']],
        'MaxValueNameLen': [0x3c, ['unsigned long']],
        'MaxValueDataLen': [0x40, ['unsigned long']],
        'WorkVar': [0x44, ['unsigned long']],
        'NameLength': [0x48, ['unsigned short']],
        'ClassLength': [0x4a, ['unsigned short']],
        'Name': [0x4c, ['array', 1, ['unsigned short']]],
    }],
    '_CM_KEY_INDEX': [0x8, {
        'Signature': [0x0, ['unsigned short']],
        'Count': [0x2, ['unsigned short']],
        'List': [0x4, ['array', 1, ['unsigned long']]],
    }],
    '_CHILD_LIST': [0x8, {
        'Count': [0x0, ['unsigned long']],
        'List': [0x4, ['unsigned long']],
    }],
}
