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


def get_modules_names():
    return [
        # system
        ("lazagne.softwares.system.hashdump", "HashDump"),
        ("lazagne.softwares.system.chainbreaker", "ChainBreaker"),
        ("lazagne.softwares.system.system", "System"),
        # mails
        ("lazagne.softwares.mails.thunderbird", "Thunderbird"),
        # browsers
        ("lazagne.softwares.browsers.chrome", "Chrome")
    ]


def get_modules():
    modules = [soft_import(package_name, module_name)() for package_name, module_name in get_modules_names()]
    return modules + firefox_browsers
