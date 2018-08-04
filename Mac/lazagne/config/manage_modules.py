# -*- coding: utf-8 -*- 
# !/usr/bin/python

# browsers
from lazagne.softwares.browsers.mozilla import firefox_browsers
from lazagne.softwares.browsers.chrome import Chrome

# mails 
from lazagne.softwares.mails.thunderbird import Thunderbird

# system
from lazagne.softwares.system.hashdump import HashDump
from lazagne.softwares.system.chainbreaker import ChainBreaker
from lazagne.softwares.system.system import System


def get_categories():
    category = {
        'browsers': {'help': 'Web browsers supported'},
        'mails': {'help': 'Email clients supported'},
        'system': {'help': 'System credentials'},
    }
    return category


def get_modules():
    module_names = [
        Thunderbird(),
        Chrome(),
        HashDump(),
        ChainBreaker(),
        System()
    ]
    return module_names + firefox_browsers
