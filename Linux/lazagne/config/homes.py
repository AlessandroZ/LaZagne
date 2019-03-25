import pwd
import os


def directories():
    """
    Retrieve all users' homes
    """
    visited = set()

    # Get all user data stored on the Unix Password Database
    for pw in pwd.getpwall():
        if pw.pw_dir not in visited:
            yield pw.pw_dir
            visited.add(pw.pw_dir)

    # Get current user home
    if 'HOME' in os.environ:
        home = os.environ['HOME']
        if home not in visited:
            yield home
            visited.add(home)


def get(file=[], directory=[]):
    """
    List all existing directoryectories / files found on the disk (for all users)
    using homes.get(directory=.mozilla/firefox)
    will return if enough privilege: ["/home/user1/.mozilla/firefox", "/home/user2/.mozilla/firefox"]
    """
    files = file if (type(file) in (tuple, list)) else [file]
    dirs = directory if (type(directory) in (tuple, list)) else [directory]

    for p in directories():
        if files:
            for file in files:
                if os.path.isfile(os.path.join(p, file)):
                    yield os.path.join(p, file)

        if dirs:
            for d in dirs:
                if os.path.isdir(os.path.join(p, d)):
                    yield os.path.join(p, d)

        if not files and not dirs and os.path.isdir(p):
            yield p


def users(file=[], directory=[]):
    files = file if (type(file) in (tuple, list)) else [file]
    dirs = directory if (type(directory) in (tuple, list)) else [directory]

    for pw in pwd.getpwall():
        if files:
            for file in files:
                if os.path.isfile(os.path.join(pw.pw_dir, file)):
                    yield pw.pw_name, os.path.join(pw.pw_dir, file)

        if dirs:
            for directory in dirs:
                if os.path.isdir(os.path.join(pw.pw_dir, directory)):
                    yield pw.pw_name, os.path.join(pw.pw_dir, directory)

        if not files and not dirs and os.path.isdir(pw.pw_dir):
            yield pw.pw_name, pw.pw_dir


def get_linux_env(pid):
    try:
        with open('/proc/%d/environ' % (int(pid))) as env:
            records = [
                record.split('=', 1) for record in env.read().split('\x00')
            ]

            return {
                record[0]: record[1] for record in records if len(record) == 2
            }
    except Exception:
        return {}


def sessions(setenv=True):
    import psutil

    visited = set()

    try:
        for process in psutil.process_iter():
            try:
                if hasattr(process, 'environ'):
                    environ = process.environ()
                else:
                    # Fallback to manual linux-only method
                    # if psutils is very old
                    environ = get_linux_env(process.pid)
            except Exception:
                continue

            if 'DBUS_SESSION_BUS_ADDRESS' not in environ:
                continue

            address = environ['DBUS_SESSION_BUS_ADDRESS']
            if address not in visited:
                uid = process.uids().effective
                previous = None
                previous_uid = None

                if setenv:
                    previous_uid = os.geteuid()

                    if not uid == previous_uid:
                        try:
                            os.seteuid(uid)
                        except Exception:
                            continue

                    if 'DBUS_SESSION_BUS_ADDRESS' in os.environ:
                        previous = os.environ['DBUS_SESSION_BUS_ADDRESS']

                    os.environ['DBUS_SESSION_BUS_ADDRESS'] = address

                try:
                    yield (uid, address)
                except Exception:
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
                            except Exception:
                                pass

                    visited.add(address)

    except AttributeError:
        # Fix AttributeError: 'module' object has no attribute 'process_iter'
        pass

    # Problems occured with this block of code => permission denied to lots of file even with sudo
    # for session_bus_directory in get(directory='.dbus/session-bus'):
    #     for envs in os.listdir(session_bus_directory):
    #         try:
    #             env_file = os.path.join(session_bus_directory, envs)
    #             uid = os.stat(env_file).st_uid
    #             with open(env_file) as env:
    #                 for line in env.readlines():
    #                     if not line.startswith('DBUS_SESSION_BUS_ADDRESS'):
    #                         continue
    #
    #                     if line.startswith('#'):
    #                         continue
    #
    #                     _, v = line.split('=', 1)
    #
    #                     if v.startswith("'") or v.startswith('"'):
    #                         v = v[1:-1]
    #
    #                     if v in visited:
    #                         continue
    #
    #                     if setenv:
    #                         previous_uid = os.geteuid()
    #                         if not previous_uid == uid:
    #                             try:
    #                                 os.seteuid(uid)
    #                             except Exception:
    #                                 continue
    #
    #                         previous = os.environ['DBUS_SESSION_BUS_ADDRESS']
    #                         os.environ['DBUS_SESSION_BUS_ADDRESS'] = address
    #
    #                     try:
    #                         yield (uid, v)
    #
    #                     finally:
    #
    #                         if setenv:
    #                             os.environ['DBUS_SESSION_BUS_ADDRESS'] = previous
    #                             if previous_uid != uid:
    #                                 try:
    #                                     os.seteuid(previous_uid)
    #                                 except Exception:
    #                                     pass
    #
    #         except Exception:
    #             pass
