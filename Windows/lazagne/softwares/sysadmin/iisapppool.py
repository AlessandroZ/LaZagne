import fnmatch
import os
import subprocess
import re
import string

from lazagne.config.module_info import ModuleInfo

class IISAppPool(ModuleInfo):
    def __init__(self):
        ModuleInfo.__init__(self, name='iisapppool', category='sysadmin', registry_used=True, winapi_used=True)

    def find_files(self, path, file):
        """
        Try to find all files with the same name
        """
        founded_files = []
        for dirpath, dirnames, files in os.walk(path):
            for file_name in files:
                if fnmatch.fnmatch(file_name, file):
                    founded_files.append(dirpath + '\\' + file_name)

        return founded_files

    def execute_get_stdout(self, exe_file, arguments):
        try:
            proc = subprocess.Popen(exe_file + " " + arguments, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        except:
            self.debug(u'Error executing {exefile}'.format(exefile=exe_file))
            return None

        return proc.stdout

    def run(self):
        pfound = []

        exe_files = self.find_files(os.environ['WINDIR'] + '\\System32\\inetsrv', 'appcmd.exe')
        if len(exe_files) == 0:
            self.debug(u'File not found appcmd.exe')
            return

        self.info(u'appcmd.exe files found: {files}'.format(files=exe_files))
        output = self.execute_get_stdout(exe_files[-1], 'list apppool')
        if output == None:
            self.debug(u'Problems with Application Pool list')
            return

        app_list = []
        for line in output.readlines():
            app_list.append(re.findall(r'".*"', line)[0].split('"')[1])
            

        for app in app_list:
            values = {}
            username = ''
            password = ''
            
            output = self.execute_get_stdout(exe_files[-1], 'list apppool ' + app + ' /text:*')

            for line in output.readlines():
                if re.search(r'userName:".*"', line):
                    username = re.findall(r'userName:".*"', line)[0].split('"')[1]

                if re.search(r'password:".*"', line):				
                    password = re.findall(r'password:".*"', line)[0].split('"')[1]

            if password != '' : 
                values['AppPool.Name'] = app 
                values['Username'] = username 
                values['Password'] = password 

                pfound.append(values)
				
        
        return pfound 
