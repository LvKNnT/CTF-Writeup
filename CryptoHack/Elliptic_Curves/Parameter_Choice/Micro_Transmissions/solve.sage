from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
from sage.all import *

# 1. Setup Parameters from output.txt
p = 99061670249353652702595159229088680425828208953931838069069584252923270946291
a = 1
b = 4
E = EllipticCurve(GF(p), [a,b])

# Generator G
G = E(43190960452218023575787899214023014938926631792651638044680168600989609069200 , 
      20971936269255296908588589778128791635639992476076894152303569022736123671173)

# Alice's Public Key (X-coord only)
alice_x = ZZ(87360200456784002948566700858113190957688355783112995047798140117594305287669)

# Bob's Public Key (X-coord only) - Needed to calculate Shared Secret
bob_x = ZZ(6082896373499126624029343293750138460137531774473450341235217699497602895121)
B = E.lift_x(bob_x)

# Ciphertext info
iv = bytes.fromhex('ceb34a8c174d77136455971f08641cc5')
encrypted_flag = bytes.fromhex('b503bf04df71cfbd3f464aec2083e9b79c825803a4d4a43697889ad29eb75453')

print("[*] Attempting to solve Discrete Log...")

# 2. Recover n_a (Alice's private key)
# Because lift_x might give us P or -P, we try both.
# We know n_a is 64 bits, so we set bounds for BSGS/Pollard's Lambda.
n_a = None
A_candidates = E.lift_x(alice_x, all=True)

for A_try in A_candidates:
    try:
        # Check for n_a in range [1, 2^64]
        # operation='+' is for additive group (Elliptic Curves)
        n_a = discrete_log(A_try, G, operation='+', bounds=(1, 2**64))
        print(f"[+] Found n_a: {n_a}")
        break
    except ValueError:
        continue

if n_a is None:
    print("[-] Failed to find private key.")
    exit()

# 3. Calculate Shared Secret
# S = n_a * P_b
S = n_a * B
secret_x = S.xy()[0]
print(f"[*] Shared Secret (x): {secret_x}")

# 4. Decrypt
# Derive Key
sha1 = hashlib.sha1()
sha1.update(str(secret_x).encode('ascii'))
key = sha1.digest()[:16]

# Decrypt
try:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # CORRECT WAY: Decrypt -> Unpad
    plaintext = cipher.decrypt(encrypted_flag)
    flag = unpad(plaintext, 16)
    print(f"\n[SUCCESS] Flag: {flag.decode()}")
except Exception as e:
    print(f"\n[ERROR] Decryption failed: {e}")