# -*- coding: utf-8 -*- 
import tempfile
import random
import string
import time
import os

date = time.strftime("%d%m%Y_%H%M%S")
tmp = tempfile.gettempdir()


class constant():
    folder_name = '.'
    file_name_results = 'credentials_{current_time}'.format(
        current_time=date
    )  # The extension is added depending on the user output choice
    max_help = 27
    CURRENT_VERSION = '2.4.3' 
    output = None
    modules_dic = {}
    nb_password_found = 0  # Total password found
    password_found = []  # Tab containing all passwords used for dictionary attack
    stdout_result = []  # Tab containing all results by user
    pypykatz_result = {}
    finalResults = {}
    profile = {
        'APPDATA': u'{drive}:\\Users\\{user}\\AppData\\Roaming\\',
        'USERPROFILE': u'{drive}:\\Users\\{user}\\',
        'HOMEDRIVE': u'{drive}:',
        'HOMEPATH': u'{drive}:\\Users\\{user}',
        'ALLUSERSPROFILE': u'{drive}:\\ProgramData',
        'COMPOSER_HOME': u'{drive}:\\Users\\{user}\\AppData\\Roaming\\Composer\\',
        'LOCALAPPDATA': u'{drive}:\\Users\\{user}\\AppData\\Local',
    }
    username = u''
    keepass = {}
    hives = {
        'sam': os.path.join(
            tmp,
            ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))])),
        'security': os.path.join(
            tmp,
            ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))])),
        'system': os.path.join(
            tmp,
            ''.join([random.choice(string.ascii_lowercase) for x in range(0, random.randint(6, 12))]))
    }
    quiet_mode = False
    st = None  # Standard output
    drive = u'C'
    user_dpapi = None
    system_dpapi = None
    lsa_secrets = None
    is_current_user = False  # If True, Windows API are used otherwise dpapi is used
    user_password = None
    wifi_password = False  # Check if the module as already be done
    module_to_exec_at_end = {
        "winapi": [],
        "dpapi": [],
    }
