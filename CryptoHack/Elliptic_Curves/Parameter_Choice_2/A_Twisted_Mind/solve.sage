from sage.all import *
from pwn import remote
import json

p = 2**192 - 237
a = -3
b = 1379137549983732744405137513333094987949371790433997718123
order = 6277101735386680763835789423072729104060819681027498877478

# tìm d sao cho Q = G * d (mod order(G))
def pohlig_hellman(Q, G):
    d_remainders = []
    small_modulus = []

    n = G.order()
    factors = factor(n)[:-1] # bỏ đi ước cuối nhé
    
    for q, e in factors:
        # nhóm con của Q và G
        small_Q = Q * (n // (q**e))
        small_G = G * (n // (q**e))
        
        small_d = discrete_log(small_Q, small_G, operation = "+")
        
        d_remainders.append(small_d)
        small_modulus.append(q**e)

    d = crt(d_remainders, small_modulus)
    big_modulus = prod(small_modulus)
    
    return d, big_modulus

# Đường cong E GF(p)
E = EllipticCurve(GF(p), [a, b])
# Twist của E

non_square = -1
assert Mod(non_square, p).is_square() == false
twist = E.quadratic_twist(non_square)
# Đường cong E trên GF(p^2)
E2 = EllipticCurve(GF((p, 2), "k"), [a, b])


# giờ ta tìm hai điểm P và Q có order bằng với order của E và twist
P = E2.lift_x(ZZ(randint(1, p)))
while P.order() != E.order():
    P = E2.lift_x(ZZ(randint(1, p)))

Q = E2.lift_x(ZZ(randint(1, p)))
while Q.order() != twist.order():
    Q = E2.lift_x(ZZ(randint(1, p)))

print(f"{P = }")
print(f"{Q = }")

io = remote("socket.cryptohack.org", 13416)
io.recvuntil(b'You have 120 seconds to submit the private key in decimal format.\n')

d_res = []
moduli = []
# Giờ ta gửi P và Q để thực hiện Pohlig hellman
for point in [P, Q]:
    payload = {"option": "get_pubkey", 'x0': int(point[0])}
    io.sendline(json.dumps(payload).encode())
    public_key = json.loads(io.recvline().decode())
        
    # Vì yA chỉ được lấy một trường hợp nên giá trị d có thể bị đổi dấu 
    A = E2.lift_x(ZZ(public_key["pubkey"]))
    
    # A = B * d
    d_remainders, modulus = pohlig_hellman(A, point)
    d_res.append(d_remainders)
    moduli.append(modulus)

# giờ ta sẽ CRT hệ sau là có d, nhưng phải chia 4 trường hợp ra nhé
# d = d_res[0] (mod moduli[0])
# d = d_res[1] (mod moduli[1])

# d = -d_res[0] (mod moduli[0])
# d = d_res[1] (mod moduli[1])

# d = d_res[0] (mod moduli[0])
# d = -d_res[1] (mod moduli[1])

# d = -d_res[0] (mod moduli[0])
# d = -d_res[1] (mod moduli[1])

# 4 trường hợp thì cũng ít, nhưng mà mình code cái này cho nó tổng quát lun, sau này dùng lại
from itertools import product
sign_remainders = []
for signs in product([1, -1], repeat=len(d_res)):
    signed = [sign * val for sign, val in zip(signs, d_res)]
    sign_remainders.append(signed)

private_key = []
for d_r in sign_remainders:
    private_key.append(crt(d_r, moduli))
    
for i in private_key:
    payload = {"option": "get_flag", "privkey": int(i)}
    io.sendline(json.dumps(payload).encode())
io.interactive()
