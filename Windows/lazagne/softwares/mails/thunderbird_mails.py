from lazagne.config.soft_import_module import soft_import

mozilla_module_location = "lazagne.softwares.browsers.mozilla", "Mozilla"
Mozilla = soft_import(*mozilla_module_location)

# Name, path
thunderbird_mails = [
    (u'epyrus', u'{APPDATA}\\athenian200\\Epyrus'),
    (u'interlink', u'{APPDATA}\\BinaryOutcast\\Interlink'),
    (u'thunderbird', u'{APPDATA}\\Thunderbird'),
]

thunderbird_mails = [Mozilla(browser_name=name, path=path, category='mails') for name, path in thunderbird_mails]
