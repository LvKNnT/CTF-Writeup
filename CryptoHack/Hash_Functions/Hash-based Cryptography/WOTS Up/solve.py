import hashlib
import json
from os import urandom
from Crypto.Cipher import AES

BYTE_MAX = 255
KEY_LEN = 32

test_sig = b""

class Winternitz:
    def __init__(self, priv_seed=urandom(KEY_LEN)):
        self.priv_key = []
        for _ in range(KEY_LEN):
            priv_seed = self.hash(priv_seed)
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
        # print(data_hash.hex())
        data_hash_bytes = bytearray(data_hash)
        # for b in data_hash_bytes:
            # print(hex(b))
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
        print(signature[0].hex())
        
        verify = []
        for i in range(KEY_LEN):
            verify_item = signature[i]
            hash_iters = data_hash_bytes[i] + 1
            for _ in range(hash_iters):
                verify_item = self.hash(verify_item)
            verify.append(verify_item)
        return self.pub_key == verify, signature
    
w = Winternitz()

message1 = b"WOTS Up???"
signature1 = w.sign(message1)
assert w.verify(signature1, message1)[0]
test_sig = w.verify(signature1, message1)[1]

message2 = b"Sign for flag"
signature2 = w.sign(message2)
assert w.verify(signature2, message2)

public_key = []
message = b""
signature = []
iv = b""
enc = b""

with open("data.json", "r") as f:
    data = json.load(f)
    public_key = [bytes.fromhex(s) for s in data["public_key"]]
    message = data["message"].encode()
    signature = [bytes.fromhex(s) for s in data["signature"]]
    iv = bytes.fromhex(data["iv"])
    enc = bytes.fromhex(data["enc"])

# print(signature[0].hex())
# signature = test_sig # test
seed = []
rank = []
for i in range(KEY_LEN):
    rank.append(hashlib.sha256(message2).digest()[i] - i)

dif = hashlib.sha256(message1).digest()[0] - hashlib.sha256(message2).digest()[0] - 1
rank[0] += 1
base_sus = signature[0]

for _ in range(dif):
    base_sus = w.hash(base_sus)

seed.append(w.hash(base_sus)[0])

for i in range(1, KEY_LEN):
    dif = rank[0] - rank[i]
    print(f"dif: {dif}")

    sus_sig = base_sus
    for _ in range(dif):
        sus_sig = w.hash(sus_sig)

    seed.append(sus_sig[0])

aes_key = bytes(seed)
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(enc)
print(decrypted)