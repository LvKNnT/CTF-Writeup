import requests
response = requests.get("https://web.cryptohack.org/rsa-or-hmac-2/create_session/sybau")
token1 = response.json()["session"]
response = requests.get("https://web.cryptohack.org/rsa-or-hmac-2/create_session/67")
token2 = response.json()["session"]

print(token1)
print(token2)

# $ docker run --rm -it portswigger/sig2n <token1> <token2>

import jwt, base64

PUBLIC_KEY = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJDZ0tDQVFFQTdwZ2J1UDZYOFhIeUZyNDd5YlNyMXlUK20rK0ZObi9mVW5uS1AxMTNiWWJjcC9KbjRubDUKa2lSb0s0Y2dYV3Y2eVlhVHhWTVN5dkxjZERrUHNtWjBKNERmQlhaU3BVS1kyUUsrb1I3Nm5iNWZaK1ZOVUVpMApJdTE1R0JKZElQajh5RUE4MU92aUROY25YUnlEcExCV3RYWjFnTkp5dm9pT2ovM0RnUmNJV3o5eUpOa3plOGxuCnV0TU96eG9iZy9vMmk5b2V3YTJNSmsrTUhLVVpPT0N4b2FWZm1kY3pUcURJWGRvd3huV0NURWdXYjRTQk4rTUgKR3UrOHBXZ0dxWENpb0dEUEFMSFJSOThDV29wSEMwejdWaWEvVVhrTE5HQ2pKZmROWmlKRm5MSEc4dEFURHZEUwpDRFFTZzQ2TUFSazVFaW40ZWtWUGFOS25qYzZJTm5PMDFRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"
assert PUBLIC_KEY is not None

# python3.8 -m pip install pyjwt==1.5.0
PUBLIC_KEY = base64.b64decode(PUBLIC_KEY)
token = jwt.encode({"admin" : True}, PUBLIC_KEY, algorithm='HS256')
response = requests.get(f"https://web.cryptohack.org/rsa-or-hmac-2/authorise/{token.decode()}/")
print(response.json()["response"])