# -*- coding: utf-8 -*-
import os

from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.softwares.browsers.chromium_based import ChromiumBased


class UCBrowser(ChromiumBased):
    def __init__(self):
        self.database_query = 'SELECT action_url, username_value, password_value FROM wow_logins'
        ModuleInfo.__init__(self, 'uc browser', 'browsers', winapi_used=True)

    def _get_database_dirs(self):
        data_dir = u'{LOCALAPPDATA}\\UCBrowser'.format(**constant.profile)
        try:
            # UC Browser seems to have random characters appended to the User Data dir so we'll list them all
            self.paths = [os.path.join(data_dir, d) for d in os.listdir(data_dir)]
        except Exception:
            self.paths = []
        return ChromiumBased._get_database_dirs(self)
