import hashlib
from sage.all import *
from pwn import *

HOST = 'chall.blackpinker.com'
PORT = 20229
io = remote(HOST, PORT)

# --- 1. Variables from the Server ---
# Replace these with the actual values printed by the CTF server

g = int(io.recvline_contains(b'g = ').decode().strip().split('= ')[1])  # The 256-bit prime g # The 256-bit modulus N

# Our chosen inputs
y = 2
logT = 50
T = 2 ^ logT

io.recvuntil(b'y: ')
io.sendline(str(y).encode())

N = int(io.recvline_contains(b'N = ').decode().strip().split('= ')[1])

io.recvuntil(b'logT: ')
io.sendline(str(logT).encode())

# --- 2. Helper Function ---
def hash_to_prime(g_val, y_val, T_val):
    h = hashlib.sha256(f"{g_val}_{y_val}_{T_val}".encode()).digest()
    p_val = int.from_bytes(h, 'big')
    # Use Sage's built-in prime checker
    while not is_prime(p_val):
        p_val += 1
    return p_val

print("[*] Factoring N...")
# Sage will factor this 256-bit N almost instantly
factors = factor(N)
p = factors[0][0]
q = factors[1][0]
print(f"[+] Found p: {p}")
print(f"[+] Found q: {q}")

# Calculate Euler's totient
phi = (p - 1) * (q - 1)

print("[*] Computing verification parameters l and r...")
l = hash_to_prime(g, y, T)
r = power_mod(2, T, l)

print("[*] Forging the proof...")
# d = l^-1 mod phi
d = inverse_mod(l, phi)

# g^-r mod N
g_inv_r = inverse_mod(power_mod(g, r, N), N)

# pi = (y * g^-r)^d mod N
base = (y * g_inv_r) % N
pi = power_mod(base, d, N)

print("\n=== EXPLOIT PAYLOADS ===")
io.recvuntil(b'pi: ')
io.sendline(str(pi).encode())
response = io.recvall().decode()
print(response)