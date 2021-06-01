#!/usr/bin/env python
# -*- coding: utf-8 -*-

from importlib import import_module

from lazagne.config.module_info import ModuleInfo


def soft_import(package_name, module_name):
    """ Imports module or return mock object which only print error
    """
    try:
        module = import_module(package_name)
        return getattr(module, module_name)
    except ImportError as ex:

        #  Emulate import ModuleInfo: return object (function) which generates objects of type ModuleInfo
        #  This could be done with metaclasses, but now let's just keep it simple.
        def get_import_error_mock(module_name, exception):
            return lambda *args, **kwargs: _MOCK_ImportErrorInModule(module_name, exception)

        return get_import_error_mock(module_name, ex)


class _MOCK_ImportErrorInModule(ModuleInfo):

    def __init__(self, name, exception):
        super(_MOCK_ImportErrorInModule, self).__init__(name, "unused")
        self.__message_to_print = "Module %s is not used due to unresolved dependence:\r\n%s" % (name, str(exception))

    def run(self):
        self.error(self.__message_to_print)
