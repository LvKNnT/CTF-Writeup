from hashlib import sha256
import os

challenges = []

with open("output.txt", "r") as f:
    for line in f:
        challenges.append(eval(line.strip()))

def checktest(a, b, c, d, root):
    left = sha256(bytes.fromhex(a) + bytes.fromhex(b)).digest()
    right = sha256(bytes.fromhex(c) + bytes.fromhex(d)).digest()
    return sha256(left + right).hexdigest() == root

flag = ""

for a, b, c, d, root in challenges:
    if checktest(a, b, c, d, root):
        flag += "1"
    else:
        flag += "0"

print(bytes.fromhex(hex(int(flag, 2))[2:]).decode())