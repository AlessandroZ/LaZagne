# -*- coding: utf-8 -*- 
# !/usr/bin/python
from lazagne.config.soft_import_module import soft_import
from lazagne.softwares.browsers.firefox_browsers import firefox_browsers


def get_categories():
    category = {
        'browsers': {'help': 'Web browsers supported'},
        'mails': {'help': 'Email clients supported'},
        'system': {'help': 'System credentials'},
        'unused': {'help': 'This modules could not be used because of broken dependence'}
    }
    return category


def get_modules():
    module_names = [
        # system
        soft_import("lazagne.softwares.system.hashdump", "HashDump")(),
        soft_import("lazagne.softwares.system.chainbreaker", "ChainBreaker")(),
        soft_import("lazagne.softwares.system.system", "System")(),
        # mails
        soft_import("lazagne.softwares.mails.thunderbird", "Thunderbird")(),
        # browsers
        soft_import("lazagne.softwares.browsers.chrome", "Chrome")(),
    ]
    return module_names + firefox_browsers
