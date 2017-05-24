import pwd
import os

def directories():
    visited = set()

    for pw in pwd.getpwall():
        if not pw.pw_dir in visited:
            yield pw.pw_dir
            visited.add(pw.pw_dir)

    if 'HOME' in os.environ:
        home = os.environ['HOME']
        if not home in visited:
            yield home
            visited.add(home)


def get(file=[], dir=[]):

    files = file if (type(file) in (tuple, list)) else [file]
    dirs = dir if (type(dir) in (tuple, list)) else [dir]

    for p in directories():
        if files:
            for file in files:
                if os.path.isfile(os.path.join(p, file)):
                    yield os.path.join(p, file)

        if dirs:
            for dir in dirs:
                if os.path.isdir(os.path.join(p, dir)):
                    yield os.path.join(p, dir)

        if not files and not dirs and os.path.isdir(p):
            yield p

def users(file=[], dir=[]):
    files = file if (type(file) in (tuple, list)) else [file]
    dirs = dir if (type(dir) in (tuple, list)) else [dir]

    for pw in pwd.getpwall():
        if files:
            for file in files:
                if os.path.isfile(os.path.join(pw.pw_dir, file)):
                    yield pw.pw_name, os.path.join(pw.pw_dir, file)

        if dirs:
            for dir in dirs:
                if os.path.isdir(os.path.join(pw.pw_dir, dir)):
                    yield pw.pw_name, os.path.join(pw.pw_dir, dir)

        if not files and not dirs and os.path.isdir(pw.pw_dir):
            yield pw.pw_name, pw.pw_dir

def get_linux_env(pid):
    try:
        with open('/proc/%d/environ'%(int(pid))) as env:
            records = [
                record.split('=', 1) for record in env.read().split('\x00')
            ]

            return {
                record[0]:record[1] for record in records if len(record) == 2
            }
    except:
        return {}

def sessions(setenv=True):
    import psutil

    visited = set()

    for process in psutil.process_iter():
        try:
            if hasattr(process, 'environ'):
                environ = process.environ()
            else:
                # Fallback to manual linux-only method
                # if psutils is very old
                environ = get_linux_env(process.pid)
        except:
            continue

        if not 'DBUS_SESSION_BUS_ADDRESS' in environ:
            continue

        address = environ['DBUS_SESSION_BUS_ADDRESS']
        if not address in visited:
            uid = process.uids().effective

            if setenv:
                previous_uid = os.geteuid()
                previous = None
                if not uid == previous_uid:
                    try:
                        os.seteuid(uid)
                    except:
                        continue

                if 'DBUS_SESSION_BUS_ADDRESS' is os.environ:
                    previous = os.environ['DBUS_SESSION_BUS_ADDRESS']

                os.environ['DBUS_SESSION_BUS_ADDRESS'] = address

            try:
                yield (uid, address)
            except Exception, e:
                pass
            finally:
                if setenv:
                    if previous:
                        os.environ['DBUS_SESSION_BUS_ADDRESS'] = previous
                    else:
                        del os.environ['DBUS_SESSION_BUS_ADDRESS']

                    if previous_uid != uid:
                        try:
                            os.seteuid(previous_uid)
                        except:
                            pass

                visited.add(address)

    for session_bus_dir in get(dir='.dbus/session-bus'):
        for envs in os.listdir(session_bus_dir):
            try:
                env_file = os.path.join(session_bus_dir, envs)
                uid = os.stat(env_file).st_uid
                with open(env_file) as env:
                    for line in env.readlines():
                        if not line.startswith('DBUS_SESSION_BUS_ADDRESS'):
                            continue

                        if line.startswith('#'):
                            continue

                        _, v = line.split('=', 1)

                        if v.startswith("'") or v.startswith('"'):
                            v = v[1:-1]

                        if v in visited:
                            continue

                        if setenv:
                            previous_uid = os.geteuid()
                            if not previous_uid == uid:
                                try:
                                    os.seteuid(uid)
                                except:
                                    continue

                            previous = os.environ['DBUS_SESSION_BUS_ADDRESS']
                            os.environ['DBUS_SESSION_BUS_ADDRESS'] = address

                        try:
                            yield (uid, v)

                        finally:

                            if setenv:
                                os.environ['DBUS_SESSION_BUS_ADDRESS'] = previous
                                if previous_uid != uid:
                                    try:
                                        os.seteuid(previous_uid)
                                    except:
                                        pass

            except Exception, e:
                pass
