from sage.all import *
import numpy as np
from random import SystemRandom
from Crypto.Util.number import bytes_to_long, long_to_bytes

n = 64
m = 512
q = 0x10000
dtype = np.uint16

with open("public_key.txt") as f:
    pk = np.loadtxt(f, dtype=dtype)

with open("ciphertexts.txt") as f:
    ciphertexts = np.loadtxt(f, dtype=dtype)

A_full = matrix(Zmod(q), pk[:n, :])
b_full = vector(Zmod(q), pk[n, :])

m_eff = 2 * n

A = A_full[:, :m_eff]
A = matrix(ZZ, A_full[:, :m_eff])
b = vector(ZZ, b_full[:m_eff])

Identity_q = q * identity_matrix(ZZ, m_eff)

Lattice = matrix(ZZ, m_eff + n + 1, m_eff + 1)
Lattice.set_block(0, 0, A)
Lattice.set_block(n, 0, Identity_q)
Lattice.set_block(m_eff + n, 0, matrix(ZZ, 1, m_eff, -b))
Lattice[m_eff + n, m_eff] = 1

print("Running LLL...")
L_reduced = Lattice.LLL()

e_vector = None

for row in L_reduced:
    if row[m_eff] == 1:
        e_vector = vector(ZZ, row[:m_eff])
        break
    elif row[m_eff] == -1:
        e_vector = vector(ZZ, -row[:m_eff])
        break

if e_vector is None:
    print("Error vector not found!")
    exit(1)

A_ctx = matrix(Zmod(q), A)                  # Rectangular matrix (64 x m_use)
b_clean = vector(Zmod(q), b + e_vector) # Vector length m_use

try:
    # Solve s * A = b_clean
    s = A_ctx.solve_left(b_clean)
    print("Secret s recovered successfully!")
except ValueError:
    print("Could not solve linear system. Try increasing m_use.")
    exit()

# 7. Decrypt
sk = vector(ZZ, list(-s) + [1])

print("Decrypting...")
msg_bits = []
for c in ciphertexts:
    c_vec = vector(ZZ, c)
    # LWE Decryption: <sk, c> gives (message + even_error)
    # Modulo q, then Modulo 2 recovers message
    decrypted_val = sk.dot_product(c_vec) % q
    bit = decrypted_val % 2
    msg_bits.append(bit)

# 8. Reconstruct Flag
flag_int = 0
for bit in msg_bits:
    flag_int = (flag_int << 1) | int(bit)

print(long_to_bytes(flag_int).decode(errors='ignore'))