import os, sys

from lazagne.config.write_output import print_debug
from lazagne.config.moduleInfo import ModuleInfo
from lazagne.config import homes

class libsecret(ModuleInfo):
    def __init__(self):
        options = {'command': '-l', 'action': 'store_true', 'dest': 'SecretStorage', 'help': 'SecretStorage'}
        ModuleInfo.__init__(self, 'libsecret', 'wallet', options)

    def run(self, software_name = None):
        items = []
        visited = set()
        try:
            import dbus
            import secretstorage
            import datetime
        except Exception as e:
            print_debug('ERROR', 'libsecret: {0}'.format(e))
            return []

        for _, session in homes.sessions():
            try:
                bus = dbus.bus.BusConnection(session)

                if not 'org.freedesktop.secrets' in [ str(x) for x in bus.list_names() ]:
                    continue

                collections = list(secretstorage.collection.get_all_collections(bus))

            except Exception, e:
                print e
                continue

            for collection in collections:
                if collection.is_locked():
                    continue

                label = collection.get_label()
                if label in visited:
                    continue

                visited.add(label)

                try:
                    storage = collection.get_all_items()
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
                        'collection': label,
                    }

                    for k, v in item.get_attributes().iteritems():
                        values[unicode(k)] = unicode(v)
                    items.append(values)

            bus.flush()
            bus.close()

        return items
