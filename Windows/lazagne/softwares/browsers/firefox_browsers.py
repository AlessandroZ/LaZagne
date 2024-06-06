from lazagne.config.soft_import_module import soft_import


mozilla_module_location = "lazagne.softwares.browsers.mozilla", "Mozilla"

Mozilla = soft_import(*mozilla_module_location)

# Name, path
firefox_browsers = [
    (u'firefox', u'{APPDATA}\\Mozilla\\Firefox'),
    (u'blackHawk', u'{APPDATA}\\NETGATE Technologies\\BlackHawk'),
    (u'cyberfox', u'{APPDATA}\\8pecxstudios\\Cyberfox'),
    (u'comodo IceDragon', u'{APPDATA}\\Comodo\\IceDragon'),
    (u'k-Meleon', u'{APPDATA}\\K-Meleon'),
    (u'icecat', u'{APPDATA}\\Mozilla\\icecat'),
    (u'pale Moon', u'{APPDATA}\\Moonchild Productions\\Pale Moon'),
    (u'basilisk', u'{APPDATA}\\Basilisk-Dev\\Basilisk'),
]

firefox_browsers = [Mozilla(browser_name=name, path=path) for name, path in firefox_browsers]
