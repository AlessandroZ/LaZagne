from lazagne.config.soft_import_module import soft_import

mozilla_module_location = "lazagne.softwares.browsers.mozilla", "Mozilla"
Mozilla = soft_import(*mozilla_module_location)

# Name, path
firefox_browsers = [
    (u'firefox', u'.mozilla/firefox'),
    (u'icecat', u'.mozilla/icecat'),
    (u'waterfox', u'.waterfox'),
    # (u'Pale Moon', u'.moonchild productions/pale moon'), FIXME
]

firefox_browsers = [Mozilla(browser_name=name, path=path) for name, path in firefox_browsers]
