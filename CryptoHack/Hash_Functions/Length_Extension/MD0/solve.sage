from pwn import *
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
HOST = "localhost"
PORT = 13388
r = remote( HOST, PORT )

r.recvline()
msg1 = b"a" * 15
r.sendline( json.dumps( { "option" : "sign", "message" : msg1.hex() }).encode() )

out = json.loads(r.recvline().decode())["signature"]
out = bytes.fromhex( out )
def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

msg2 = pad( b"admin=Trueaaaaa", 16 )
out = bxor(AES.new(msg2, AES.MODE_ECB).encrypt(out), out)
#842a4b11c18327b63ea7a87c813ec6fc
send = msg1 + b"\x01" + b"admin=Trueaaaaa"
r.sendline( json.dumps( { "option" : "get_flag", "signature" : out.hex(), "message" : send.hex() }).encode() )
print( r.recvline() )
