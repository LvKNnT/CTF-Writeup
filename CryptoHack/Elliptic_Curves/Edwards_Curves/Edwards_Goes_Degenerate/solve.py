from sympy.ntheory import discrete_log
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha1

# 1. Challenge Parameters
p = 110791754886372871786646216601736686131457908663834453133932404548926481065303
base_y = 11

# From the output file
y_alice = 109790246752332785586117900442206937983841168568097606235725839233151034058387
y_bob = 45290526009220141417047094490842138744068991614521518736097631206718264930032

iv_hex = '31068e75b880bece9686243fa4dc67d0'
encrypted_flag_hex = 'e2ef82f2cde7d44e9f9810b34acc885891dad8118c1d9a07801639be0629b186dc8a192529703b2c947c20c4fe5ff2c8'

print(f"[*] Solving Discrete Logarithm for n_A...")
print(f"    Target: {y_alice} = {base_y}^n_A (mod p)")

# 2. Solve DLP to find Alice's private key (n_a)
# This works efficiently because p-1 is smooth for this challenge
n_alice = discrete_log(p, y_alice, base_y)

print(f"[+] Found Alice's private key: {n_alice}")

# 3. Compute Shared Secret
# The operation reduces to modular exponentiation: S = y_bob ^ n_alice (mod p)
shared_secret_y = pow(y_bob, n_alice, p)
print(f"[+] Calculated Shared Secret: {shared_secret_y}")

# 4. Decrypt Flag
# Replicate the key derivation logic from the source
key = sha1(str(shared_secret_y).encode('ascii')).digest()[:16]
iv = bytes.fromhex(iv_hex)
ciphertext = bytes.fromhex(encrypted_flag_hex)

cipher = AES.new(key, AES.MODE_CBC, iv)
try:
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    print(f"\n[SUCCESS] Flag: {plaintext.decode()}")
except Exception as e:
    print(f"\n[ERROR] Decryption failed: {e}")