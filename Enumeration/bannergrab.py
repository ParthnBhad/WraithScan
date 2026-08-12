from requests import get
def banner(ip):
    try:
        response = get('https://api.hackertarget.com/bannerlookup/?q=' + ip)
        if(response.status_code == 200):
            print(response.text)
        else:
            print("Error getting banner")
    except Exception as e:
        print(e)