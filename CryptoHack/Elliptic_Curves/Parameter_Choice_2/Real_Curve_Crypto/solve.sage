import json
from mpmath import mp
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad
from sage.all import Matrix, ZZ

# 1. Setup precision
mp.dps = 200

# 2. Load the leaked parameters
output_file = 'output_8d82e413d29d7810ee8eff5d1226453d.txt'
with open(output_file, 'r') as f:
    data = json.load(f)

gx = mp.mpf(data['gx'])
gy = mp.mpf(data['gy'])
px = mp.mpf(data['px'])
py = mp.mpf(data['py'])
ciphertext = bytes.fromhex(data['ciphertext'])
iv = bytes.fromhex(data['iv'])

print("[*] Computing exact elliptic integrals...")

# 3. Exact closed-form solution (No numerical integration)
omega = 2 * mp.sqrt(2) * mp.ellipk(0.5)

def get_u(x, y):
    phi = mp.asin(mp.sqrt(2 / (x + 1)))
    val = mp.sqrt(2) * mp.ellipf(phi, 0.5)
    if y < 0:
        return omega - val 
    return val

u_G = get_u(gx, gy)
u_P = get_u(px, py)

print(f"[+] Exact u_G: {u_G}")
print(f"[+] Exact u_P: {u_P}")
print(f"[+] Exact omega: {omega}")

# 4. Construct the Lattice
print("[*] Building the lattice...")
SCALE = 10**150
K_WEIGHT = 2**128 

W_scaled = int(omega * SCALE)
U_G_scaled = int(u_G * SCALE)
U_P_scaled = int(u_P * SCALE)

M = Matrix(ZZ, [
    [W_scaled,   0, 0],
    [U_G_scaled, 1, 0],
    [-U_P_scaled, 0, K_WEIGHT] 
])

L = M.LLL()

# 5. Extract N and Decrypt
N = None
for row in L:
    if abs(row[2]) == K_WEIGHT:
        N = abs(row[1])
        break

if N is None:
    print("[-] LLL failed to find the scalar.")
    exit()

print(f"[+] Recovered Scalar (N): {N}")

# Reconstruct the 16-byte key
key = long_to_bytes(N).rjust(16, b'\x00')
print(f"[+] Recovered AES Key: {key.hex()}")

# Decrypt the flag
cipher = AES.new(key, AES.MODE_CBC, iv)
try:
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    print(f"\n[!] FLAG: {plaintext.decode()}")
except Exception as e:
    print(f"[-] Decryption failed: {e}")