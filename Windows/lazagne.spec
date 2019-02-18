# -*- mode: python -*-
import sys
a = Analysis(
        ['laZagne.py'],
        pathex=[''],
        hiddenimports=[],
        hookspath=None,
        runtime_hooks=None
)

for d in a.datas:
  if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

pyz = PYZ(a.pure)
exe = EXE(
        pyz,
        a.scripts,
        a.binaries + [('msvcp100.dll', 'C:\\Windows\\System32\\msvcp100.dll', 'BINARY'),
                      ('msvcr100.dll', 'C:\\Windows\\System32\\msvcr100.dll', 'BINARY')]
        if sys.platform == 'win32' else a.binaries,
        a.zipfiles,
        a.datas,
        name='lazagne.exe',
        debug=False,
        strip=None,
        upx=True,
        console=True
)
