# -*- coding: utf-8 -*-
# !/usr/bin/python
import getpass
import traceback
from collections import OrderedDict

from lazagne.config.write_output import print_debug, StandardOutput
from lazagne.config.constant import constant
from lazagne.config.manage_modules import get_categories, get_modules


def create_module_dic():
    if constant.modules_dic:
        return constant.modules_dic

    modules = {}

    # Define a dictionary for all modules
    for category in get_categories():
        modules[category] = {}

    # Add all modules to the dictionary
    for m in get_modules():
        modules[m.category][m.options['dest']] = m

    constant.modules_dic = modules
    return modules


def run_module(module, subcategories):
    """
    Run only one module
    """
    modules_to_launch = []

    # Launch only a specific module
    for i in subcategories:
        if subcategories[i] and i in module:
            modules_to_launch.append(i)

    # Launch all modules
    if not modules_to_launch:
        modules_to_launch = module

    for i in modules_to_launch:
        try:
            constant.st.title_info(i.capitalize())  # Print title
            pwd_found = module[i].run()  # Run the module
            constant.st.print_output(i.capitalize(), pwd_found)  # Print the results

            # Return value - not used but needed
            yield True, i.capitalize(), pwd_found
        except Exception:
            error_message = traceback.format_exc()
            print_debug('DEBUG', error_message)
            yield False, i.capitalize(), error_message


def run_modules(category_selected, subcategories):
    """
    Run modules
    """
    modules = create_module_dic()
    categories = {category_selected: get_categories()[category_selected]} \
        if category_selected != 'all' else get_categories()

    # Sort dict in reverse mode to run libsecrets as first module
    for cat in OrderedDict(reversed(sorted(categories.items(), key=lambda t: t[0]))):
        for r in run_module(modules[cat], subcategories):
            yield r


def run_lazagne(category_selected='all', subcategories={}):
    """
    Main function
    """
    if not constant.st:
        constant.st = StandardOutput()

    user = getpass.getuser()
    constant.finalResults = {'User': user}

    for r in run_modules(category_selected, subcategories):
        yield r

    constant.stdout_result.append(constant.finalResults)
