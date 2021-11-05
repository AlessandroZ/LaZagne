from lazagne.config.soft_import_module import soft_import

chromium_based_module_location = "lazagne.softwares.browsers.chromium_based", "ChromiumBased"
ChromiumBased = soft_import(*chromium_based_module_location)

# Name, path
chromium_browsers_paths = [
    (u'Google Chrome', u'.config/google-chrome'),
    (u'Chromium', u'.config/chromium'),
    (u'Brave', u'.config/BraveSoftware/Brave-Browser'),
    (u'SlimJet', u'.config/slimjet'),
    (u'Dissenter Browser', u'.config/GabAI/Dissenter-Browser'),
    (u'Vivaldi', u'.config/vivaldi'),
    (u'Microsoft Edge (Dev)', u'.config/microsoft-edge-dev'),
    (u'Microsoft Edge (Beta)', u'.config/microsoft-edge-beta'),
    (u'Microsoft Edge', u'.config/microsoft-edge'),
    # (u'SuperBird', u'.config/superbird'),  # FIXME
    # (u'Whale', u'.config/naver-whale'),  # FIXME returns bytes
]

chromium_browsers = [ChromiumBased(browser_name=name, path=path) for name, path in chromium_browsers_paths]
