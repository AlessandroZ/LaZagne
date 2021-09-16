from lazagne.config.soft_import_module import soft_import


Mozilla = soft_import("lazagne.softwares.browsers.mozilla", "Mozilla")

# Name, path
firefox_browsers = [
    (u'firefox', u"~/Library/Application Support/Firefox/"),
    # Check these paths on Mac systems
    # (u'BlackHawk', u'{APPDATA}\\NETGATE Technologies\\BlackHawk'),
    # (u'Cyberfox', u'{APPDATA}\\8pecxstudios\\Cyberfox'),
    # (u'Comodo IceDragon', u'{APPDATA}\\Comodo\\IceDragon'),
    # (u'K-Meleon', u'{APPDATA}\\K-Meleon'),
    # (u'Icecat', u'{APPDATA}\\Mozilla\\icecat'),
]

firefox_browsers = [Mozilla(browser_name=name, path=path) for name, path in firefox_browsers]
