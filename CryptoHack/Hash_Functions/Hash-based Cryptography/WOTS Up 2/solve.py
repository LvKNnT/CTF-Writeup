import hashlib
import json
from os import urandom
from Crypto.Cipher import AES

BYTE_MAX = 255
KEY_LEN = 32

class Winternitz:
    def __init__(self, priv_key=None):
        self.priv_key = []
        if priv_key is not None:
            for i in range(KEY_LEN):
                self.priv_key.append(bytes.fromhex(priv_key[i]))
        else:
            for _ in range(KEY_LEN):
                priv_seed = urandom(KEY_LEN)
                self.priv_key.append(priv_seed)
        self.gen_pubkey()

    def gen_pubkey(self):
        self.pub_key = []
        for i in range(KEY_LEN):
            pub_item = self.hash(self.priv_key[i])
            for _ in range(BYTE_MAX):
                pub_item = self.hash(pub_item)
            self.pub_key.append(pub_item)

    def hash(self, data):
        return hashlib.sha256(data).digest()

    def sign(self, data):
        data_hash = self.hash(data)
        data_hash_bytes = bytearray(data_hash)
        sig = []
        for i in range(KEY_LEN):
            sig_item = self.priv_key[i]
            int_val = data_hash_bytes[i]
            hash_iters = BYTE_MAX - int_val
            for _ in range(hash_iters):
                sig_item = self.hash(sig_item)
            sig.append(sig_item)
        return sig

    def verify(self, signature, data):
        data_hash = self.hash(data)
        data_hash_bytes = bytearray(data_hash)
        verify = []
        for i in range(KEY_LEN):
            verify_item = signature[i]
            hash_iters = data_hash_bytes[i] + 1
            for _ in range(hash_iters):
                verify_item = self.hash(verify_item)
            verify.append(verify_item)
        return self.pub_key == verify

with open("data.json", "r") as f:
    data = json.load(f)

# process data
mess_len = len(data["signatures"])
message2 = f"{data['public_key'][0]} sent 999999 WOTScoins to me".encode()

signature2 = [b"" for _ in range(KEY_LEN)]

for i in range(mess_len):
    message = data["signatures"][i]["message"].encode()
    signature = [bytes.fromhex(s) for s in data["signatures"][i]["signature"]]
    
    for j in range(KEY_LEN):
        dif = hashlib.sha256(message).digest()[j] - hashlib.sha256(message2).digest()[j]

        if dif >= 0:
            cur_sig = signature[j]
            for _ in range(dif):
                cur_sig = hashlib.sha256(cur_sig).digest()

            if signature2[j] == b"":
                signature2[j] = cur_sig
                # print(f"Recovered signature part {j}: {cur_sig.hex()}")
            elif signature2[j] != cur_sig:
                print(f"Current signature {cur_sig.hex()} does not match previously recovered signature {signature2[j].hex()} for part {j}")
                print(f"Inconsistent signatures at {j}, something went wrong")
                exit(1)


iv = bytes.fromhex(data["iv"])
aes_key = bytes([s[0] for s in signature2])
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
encrypted_flag = bytes.fromhex(data["enc"])
decrypted_flag = cipher.decrypt(encrypted_flag)
print("Decrypted flag:", decrypted_flag.decode())
