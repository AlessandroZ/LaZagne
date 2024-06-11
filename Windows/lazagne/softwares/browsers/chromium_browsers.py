from lazagne.config.soft_import_module import soft_import


chromium_based_module_location = "lazagne.softwares.browsers.chromium_based", "ChromiumBased"

ChromiumBased = soft_import(*chromium_based_module_location)

# Name, path or a list of paths
chromium_browsers = [
    (u'7Star', u'{LOCALAPPDATA}\\7Star\\7Star\\User Data'),
    (u'amigo', u'{LOCALAPPDATA}\\Amigo\\User Data'),
    (u'brave', u'{LOCALAPPDATA}\\BraveSoftware\\Brave-Browser\\User Data'),
    (u'centbrowser', u'{LOCALAPPDATA}\\CentBrowser\\User Data'),
    (u'chedot', u'{LOCALAPPDATA}\\Chedot\\User Data'),
    (u'chrome beta', u'{LOCALAPPDATA}\\Google\\Chrome Beta\\User Data'),
    (u'chrome canary', u'{LOCALAPPDATA}\\Google\\Chrome SxS\\User Data'),
    (u'chromium', u'{LOCALAPPDATA}\\Chromium\\User Data'),
    (u'chromium edge', u'{LOCALAPPDATA}\\Microsoft\\Edge\\User Data'),
    (u'coccoc', u'{LOCALAPPDATA}\\CocCoc\\Browser\\User Data'),
    (u'comodo dragon', u'{LOCALAPPDATA}\\Comodo\\Dragon\\User Data'),  # Comodo IceDragon is Firefox-based
    (u'elements browser', u'{LOCALAPPDATA}\\Elements Browser\\User Data'),
    (u'DCBrowser', u'{LOCALAPPDATA}\\DCBrowser\\User Data'),
    (u'epic privacy browser', u'{LOCALAPPDATA}\\Epic Privacy Browser\\User Data'),
    (u'google chrome', u'{LOCALAPPDATA}\\Google\\Chrome\\User Data'),
    (u'kometa', u'{LOCALAPPDATA}\\Kometa\\User Data'),
    (u'opera', u'{APPDATA}\\Opera Software\\Opera Stable'),
    (u'opera gx', u'{APPDATA}\\Opera Software\\Opera GX Stable'),
    (u'orbitum', u'{LOCALAPPDATA}\\Orbitum\\User Data'),
    (u'qqbrowser', u'{LOCALAPPDATA}\\Tencent\\QQBrowser\\User Data'),
    (u'sogouExplorer', u'{APPDATA}\\SogouExplorer\\Webkit\\User Data'),
    (u'sputnik', u'{LOCALAPPDATA}\\Sputnik\\Sputnik\\User Data'),
    (u'torch', u'{LOCALAPPDATA}\\Torch\\User Data'),
    (u'uran', u'{LOCALAPPDATA}\\uCozMedia\\Uran\\User Data'),
    (u'vivaldi', u'{LOCALAPPDATA}\\Vivaldi\\User Data'),
    (u'yandexBrowser', u'{LOCALAPPDATA}\\Yandex\\YandexBrowser\\User Data')
]

chromium_browsers = [ChromiumBased(browser_name=name, paths=paths) for name, paths in chromium_browsers]
