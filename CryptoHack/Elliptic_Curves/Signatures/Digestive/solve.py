import requests
url = "https://web.cryptohack.org/digestive/"

def sign(username):
    return requests.get(url + "/sign/" + username).json()

def verify(msg, signature):
    return requests.get(url + "/verify/" + msg + "/" + signature).text

username = "a" * 1000 # Long enough username to fill payload
payload = '{"admin": false, "username": "' + username + '", "admin":true}'

out = sign(username)
flag = verify(payload, out["signature"])
print(flag)