from sage.all import *
from pwn import remote
from Crypto.Util.number import long_to_bytes
import json

# Diffie-Hellman group (512 bits), p = 2*q + 1
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Special soundness: nếu ta có hai transcript chấp nhận được (a, e1, z1) và (a, e2, z2)
# CÙNG một commitment a (tức cùng nonce r) nhưng e1 != e2 thì
#   z1 = r + e1*w (mod q)
#   z2 = r + e2*w (mod q)
#   => z1 - z2 = (e1 - e2)*w (mod q)
#   => w = (z1 - z2) / (e1 - e2) (mod q)
# Ở đây prover comment "oh no they reused the same r", nên đúng y hệt tình huống trên,
# ta chỉ cần làm verifier và gửi hai challenge khác nhau. w chính là flag.

e1 = randint(1, 2**511 - 1)
e2 = randint(1, 2**511 - 1)
assert e1 != e2

io = remote("socket.cryptohack.org", 13426)
io.recvline()  # "I will prove to you that I know flag `w` such that y = g^w mod p."

# vòng 1: prover tự gửi a (no_prompt), ta trả lời bằng e1 rồi nhận z1
res = json.loads(io.recvline().decode())
a, y = int(res["a"]), int(res["y"])
io.sendline(json.dumps({"e": int(e1)}).encode())
z1 = int(json.loads(io.recvline().decode())["z"])

# vòng 2: prover gửi lại a2, và a2 == a vì r bị reuse
res = json.loads(io.recvline().decode())
a2 = int(res["a2"])
assert a2 == a, "commitment không bị reuse, không khai thác được"
io.sendline(json.dumps({"e": int(e2)}).encode())
z2 = int(json.loads(io.recvline().decode())["z2"])

io.close()

# extract witness
w = (Integer(z1 - z2) * inverse_mod(e1 - e2, q)) % q
assert power_mod(g, int(w), p) == y

# flag đã được pad thêm os.urandom ở đuôi nên cắt bằng dấu '}'
padded = long_to_bytes(int(w))
print(padded[: padded.index(b"}") + 1].decode())
