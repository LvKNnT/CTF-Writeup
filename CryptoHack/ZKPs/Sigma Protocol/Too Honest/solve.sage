from sage.all import *
from pwn import remote
from Crypto.Util.number import long_to_bytes
import json

# RSA group 2024 bit, không ai biết order nên Girault identification không reduce z
N = 63506177426384102189597350894327047299059434133653566917776601666605133716653510828029111986956978773016660313963972378811186153674164948861199369871734498221215139927864142313488277305751745855210473314367642273303159704466900274761354992859789827863358153922459760984397971477173435625199596782211170294424560686178858124003120741008270927463303483018910205943877584647744143454984243979284973117132536957364157878132874844783228762221620863204335896952103079109039534346621267709606103312376393511653638269034043434410564414042523141936372609708140474052147124354400977541403247799192906955295291389109531010594317
g = 2

k1 = 512
k2 = 128
R = 2 ** (2 * k2 + k1)  # r được lấy random trong [0, R], R = 2^768

# Bài này prover "quá thật thà": nó tính z = r + e*flag TRÊN SỐ NGUYÊN (không mod gì cả,
# vì order của nhóm RSA là bí mật) và KHÔNG hề kiểm tra e có nằm trong [0, 2^k2) hay không.
# Bình thường e < 2^128 thì e*flag chỉ che được một phần, r ~ 2^768 vẫn giấu được flag.
# Nhưng nếu ta gửi e > R thì r trở thành "phần dư" bé xíu:
#   z = e*flag + r  với 0 <= r <= R < e   =>   flag = z // e
# Chỉ cần một transcript duy nhất là lấy được flag.

e = 2 ** 800
assert e > R

io = remote("socket.cryptohack.org", 13429)
io.recvline()  # "I will prove to you that I know flag `w` such that y = g^-w mod N"

res = json.loads(io.recvline().decode())
y, a = int(res["y"]), int(res["a"])

io.sendline(json.dumps({"e": int(e)}).encode())
z = int(json.loads(io.recvline().decode())["z"])

io.close()

flag = z // e
r = z - e * flag
assert 0 <= r <= R

# y = g^(-flag) mod N  <=>  y * g^flag = 1 mod N
assert (y * power_mod(g, int(flag), N)) % N == 1
# và transcript phải verify được: g^z = a * y^(-e)... tương đương a = g^r
assert power_mod(g, int(r), N) == a

padded = long_to_bytes(int(flag))
print(padded[: padded.index(b"}") + 1].decode())
