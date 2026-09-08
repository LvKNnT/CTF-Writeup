import time
from Crypto.Util.number import long_to_bytes
import hashlib
import json
import pwn

def generate_key():
    current_time = int(time.time())
    key = long_to_bytes(current_time)
    return hashlib.sha256(key).digest()

def decrypt(b):
    key = generate_key()
    assert len(b) <= len(key), "Data package too large to encrypt"
    plaintext = b''
    for i in range(len(b)):
        plaintext += bytes([b[i] ^ key[i]])
    return plaintext

io = pwn.remote('socket.cryptohack.org', 13372)

io.recvuntil(b'fast!\n')

flag = {
    "option": "get_flag"
}
io.sendline(json.dumps(flag).encode())
resp = io.recvline()
data = json.loads(resp.decode())
encrypted_flag = bytes.fromhex(data['encrypted_flag'])
print("[*] Encrypted flag obtained.")

print("[*] Decrypting flag...")
decrypted_flag = decrypt(encrypted_flag)
print(f"[+] Decrypted flag: {decrypted_flag.decode()}")