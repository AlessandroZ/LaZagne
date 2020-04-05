# -*- coding: utf-8 -*- 
# !/usr/bin/python

import time

date = time.strftime("%d%m%Y_%H%M%S")


class constant():
    folder_name         = '.'
    file_name_results   = 'credentials_{current_time}'.format(current_time=date)  # extension added (txt, json)
    MAX_HELP_POSITION   = 27
    CURRENT_VERSION     = '2.4.3'
    output              = None
    file_logger         = None
    verbose             = False
    nbPasswordFound     = 0         # total password found
    passwordFound       = []
    keychains_pwd       = []        # password of the keychain
    keychains_pwds      = []        # passwords contained in the keychain
    system_pwd          = []
    finalResults        = {}
    quiet_mode          = False
    st                  = None      # standard output
    dictionary_attack   = False
    user_password       = None
    user_keychain_find 	= False
    stdout_result       = []        # Tab containing all results by user
    modules_dic         = {}
