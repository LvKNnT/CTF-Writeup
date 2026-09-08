import jwt, requests, base64

# python3.8 -m pip install pyjwt==1.5.0
response = requests.get("https://web.cryptohack.org/rsa-or-hmac/get_pubkey/")
PUBLIC_KEY = response.json()["pubkey"]
token = jwt.encode({'admin': True}, PUBLIC_KEY, algorithm='HS256')
response = requests.get(f"https://web.cryptohack.org/rsa-or-hmac/authorise/{token.decode()}/")
print(response.json()["response"])
