#!/usr/bin/env python
# -*- encoding: utf-8 -*-
import time

date = time.strftime("%d%m%Y_%H%M%S")


class constant():
    folder_name         = 'results_{current_time}'.format(current_time=date)
    file_name_results   = 'credentials'  # The extension is added depending on the user output choice
    MAX_HELP_POSITION   = 27
    CURRENT_VERSION     = '1.3'
    output              = None
    file_logger         = None
    verbose             = False
    nbPasswordFound     = 0  # Total password found
    passwordFound       = []
    finalResults        = {}
    quiet_mode          = False
    st                  = None  # Standard output
