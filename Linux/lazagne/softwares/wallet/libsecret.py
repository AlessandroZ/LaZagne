import os, sys

from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config import homes

class libsecret(ModuleInfo):
    def __init__(self):
        options = {'command': '-l', 'action': 'store_true', 'dest': 'libsecret', 'help': 'libsecret'}
        ModuleInfo.__init__(self, 'libsecret', 'wallet', options)

    def run(self, software_name = None):
        items = []
        try:
            import secretstorage
            import dbus
            import datetime
        except Exception as e:
            print_debug('ERROR', 'libsecret: {0}'.format(e))
            return []

        for session in homes.sessions():
            try:
                dbus_session = dbus.SessionBus()
            except Exception, e:
                print e
                continue

            try:
                storage = secretstorage.Collection(dbus_session).get_all_items()
            except Exception, e:
                print e
                continue

            for item in storage:
                values = {
                    'created': str(datetime.datetime.fromtimestamp(item.get_created())),
                    'modified': str(datetime.datetime.fromtimestamp(item.get_modified())),
                    'content-type': item.get_secret_content_type(),
                    'label': item.get_label(),
                    'Password': item.get_secret(),
                }
                for k, v in item.get_attributes().iteritems():
                    values[str(k)] = str(v)
                items.append(values)

        return items
