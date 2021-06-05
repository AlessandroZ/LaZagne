from lazagne.config.soft_import_module import soft_import

Mozilla = soft_import("lazagne.softwares.browsers.mozilla", "Mozilla")

# Name, path
firefox_browsers = [
    (u'firefox', u'{APPDATA}\\Mozilla\\Firefox'),
    (u'blackHawk', u'{APPDATA}\\NETGATE Technologies\\BlackHawk'),
    (u'cyberfox', u'{APPDATA}\\8pecxstudios\\Cyberfox'),
    (u'comodo IceDragon', u'{APPDATA}\\Comodo\\IceDragon'),
    (u'k-Meleon', u'{APPDATA}\\K-Meleon'),
    (u'icecat', u'{APPDATA}\\Mozilla\\icecat'),
]

firefox_browsers = [Mozilla(browser_name=name, path=path) for name, path in firefox_browsers]
