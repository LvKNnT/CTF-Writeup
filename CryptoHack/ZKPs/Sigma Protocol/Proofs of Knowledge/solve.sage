from sage.all import *
from pwn import remote
import json

# Diffie-Hellman group (512 bits), p = 2*q + 1
p = 0x1ed344181da88cae8dc37a08feae447ba3da7f788d271953299e5f093df7aaca987c9f653ed7e43bad576cc5d22290f61f32680736be4144642f8bea6f5bf55ef
q = 0xf69a20c0ed4465746e1bd047f57223dd1ed3fbc46938ca994cf2f849efbd5654c3e4fb29f6bf21dd6abb662e911487b0f9934039b5f20a23217c5f537adfaaf7
g = 2

# witness w và statement y cho quan hệ g^w = y mod p, source cho sẵn luôn w
w = 0x5a0f15a6a725003c3f65238d5f8ae4641f6bf07ebf349705b7f1feda2c2b051475e33f6747f4c8dc13cd63b9dd9f0d0dd87e27307ef262ba68d21a238be00e83
y = 0x514c8f56336411e75d5fa8c5d30efccb825ada9f5bf3f6eb64b5045bacf6b8969690077c84bea95aab74c24131f900f83adf2bfe59b80c5a0d77e8a9601454e5

assert p == 2 * q + 1
assert power_mod(g, w, p) == y  # ta thật sự biết witness, nên chỉ cần chạy Schnorr trung thực

# Schnorr sigma protocol:
#   1. Prover  -> a = g^r mod p, với r random trong range(q)
#   2. Verifier-> e random trong range(0, 2^511)
#   3. Prover  -> z = r + e*w mod q
#   4. Verifier check g^z == a * y^e mod p
# vì g^z = g^(r + e*w) = g^r * (g^w)^e = a * y^e nên proof luôn pass

r = randint(1, q - 1)
a = power_mod(g, r, p)

# server yêu cầu (a % p) >= 1 và a^q = 1 mod p (a nằm trong nhóm con order q)
assert a % p >= 1 and power_mod(a, q, p) == 1

io = remote("socket.cryptohack.org", 13425)
io.recvline()  # "Prove to me that you know an w such that g^w = y mod p. ..."

io.sendline(json.dumps({"a": int(a)}).encode())
res = json.loads(io.recvline().decode())
print(res)

e = int(res["e"])
z = (r + e * w) % q

# tự check trước bằng verifier equation cho chắc
assert power_mod(g, z, p) == (a * power_mod(y, e, p)) % p

io.sendline(json.dumps({"z": int(z)}).encode())
print(json.loads(io.recvline().decode()))

io.close()
