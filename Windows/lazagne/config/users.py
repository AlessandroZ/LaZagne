# -*- coding: utf-8 -*-
# !/usr/bin/python
import os
import ctypes
import sys

from lazagne.config.winstructure import get_os_version
from lazagne.config.constant import constant


def get_user_list_on_filesystem(impersonated_user=[]):
    """
    Get user list to retrieve  their passwords
    """
    # Check users existing on the system (get only directories)
    user_path = u'{drive}:\\Users'.format(drive=constant.drive)
    if float(get_os_version()) < 6:
        user_path = u'{drive}:\\Documents and Settings'.format(drive=constant.drive)

    all_users = []
    if os.path.exists(user_path):
        all_users = [filename for filename in os.listdir(user_path) if os.path.isdir(os.path.join(user_path, filename))]

        # Remove default users
        for user in ['All Users', 'Default User', 'Default', 'Public', 'desktop.ini']:
            if user in all_users:
                all_users.remove(user)

        # Removing user that have already been impersonated
        for imper_user in impersonated_user:
            if imper_user in all_users:
                all_users.remove(imper_user)

    return all_users


def set_env_variables(user, to_impersonate=False):
    # Restore template path
    template_path = {
        'APPDATA': u'{drive}:\\Users\\{user}\\AppData\\Roaming\\',
        'USERPROFILE': u'{drive}:\\Users\\{user}\\',
        'HOMEDRIVE': u'{drive}:',
        'HOMEPATH': u'{drive}:\\Users\\{user}',
        'ALLUSERSPROFILE': u'{drive}:\\ProgramData',
        'COMPOSER_HOME': u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Composer\\',
        'LOCALAPPDATA': u'{drive}:\\Users\\{user}\\AppData\\Local',
    }

    constant.profile = template_path
    if not to_impersonate:
        # Get value from environment variables
        for env in constant.profile:
            if os.environ.get(env):
                # constant.profile[env] = os.environ.get(env)
                constant.profile[env] = os.environ.get(env)

    # Replace "drive" and "user" with the correct values
    for env in constant.profile:
        constant.profile[env] = constant.profile[env].format(drive=constant.drive, user=user)


def get_username_winapi():
    GetUserNameW = ctypes.windll.advapi32.GetUserNameW
    GetUserNameW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint)]
    GetUserNameW.restype = ctypes.c_uint

    _buffer = ctypes.create_unicode_buffer(1)
    size = ctypes.c_uint(len(_buffer))
    while not GetUserNameW(_buffer, ctypes.byref(size)):
        # WinError.h
        # define ERROR_INSUFFICIENT_BUFFER        122L    // dderror
        if ctypes.GetLastError() == 122:
            _buffer = ctypes.create_unicode_buffer(len(_buffer)*2)
            size.value = len(_buffer)
        
        else:
            return # Unusual error

    return _buffer.value
