from sage.all import *
from pwn import remote
import json

# Diffie-Hellman group (512 bits), p = 2*q + 1
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# Honest-verifier zero knowledge: vì verifier "thật thà" gửi e TRƯỚC khi ta commit,
# ta chạy đúng cái simulator dùng để chứng minh tính HVZK của Schnorr:
#   chọn z random, rồi đặt a = g^z * y^(-e) mod p
#   => a * y^e = g^z, verifier check g^z == a*y^e luôn pass
# Transcript (a, e, z) này phân phối giống hệt transcript thật, nhưng ta không cần biết w.

io = remote("socket.cryptohack.org", 13427)
io.recvline()  # "Send me a transcript for my given `e` ..."

res = json.loads(io.recvline().decode())
e, y = int(res["e"]), int(res["y"])

z = randint(1, q - 1)
# y có order q nên y^(-e) = y^((-e) mod q)
a = (power_mod(g, int(z), p) * power_mod(y, int((-e) % q), p)) % p

# server bắt a phải nằm trong nhóm con order q, g và y đều order q nên a cũng vậy
assert a % p >= 1 and power_mod(a, q, p) == 1
assert power_mod(g, int(z), p) == (a * power_mod(y, e, p)) % p

io.sendline(json.dumps({"a": int(a), "z": int(z)}).encode())
print(json.loads(io.recvline().decode()))

io.close()
