import jwt

encoded = jwt.encode({"admin": True}, key="secret", algorithm="HS256")

print(encoded)  # Print the forged JWT token