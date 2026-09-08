from pwn import *
import json
import codecs

# Connect to the server
# Replace with the actual host if not running locally
r = remote('socket.cryptohack.org', 13397) 

# Read the generated collision files
with open('collision1.bin', 'rb') as f:
    key1 = f.read()
    print(f"Key 1: {key1.hex()}")
    print("MD5 of Key 1:", codecs.encode(hashlib.md5(key1).digest(), 'hex').decode())
with open('collision2.bin', 'rb') as f:
    key2 = f.read()
    print(f"Key 2: {key2.hex()}")
    print("MD5 of Key 2:", codecs.encode(hashlib.md5(key2).digest(), 'hex').decode())

def send_key(k):
    # Convert bytes to hex string for transport
    msg = {
        "option": "insert_key",
        "key": k.hex()
    }
    r.sendline(json.dumps(msg).encode())
    print(r.recvline().decode())

print("Server Banner:", r.recvline().decode()) 

# 1. Send the first key (Starts with "CryptoHack Secure Safe")
print("Sending Key 1...")
send_key(key1)

# 2. Send the second key (Does NOT start with the prefix)
print("Sending Key 2...")
send_key(key2)

assert codecs.encode(hashlib.md5(key1).digest(), 'hex').decode() == codecs.encode(hashlib.md5(key2).digest(), 'hex').decode(), "MD5 hashes do not match, collision failed!"
# 3. Unlock the safe
print("Unlocking...")
msg = {"option": "unlock"}
r.sendline(json.dumps(msg).encode())

# 4. Receive the flag
response = r.recvline().decode()
print(response)