from sage.all import *
from pwn import remote
import json

# Parameters for 13417 (P-521 with custom b)
p = 2**521 - 1
a = -3
b = 152961
curve_order_check = 115792089237316195423570985008687907853233080465625507841270369819257950283813

# Define Curve and Twist
E = EllipticCurve(GF(p), [a, b])
# Calculate Twist Order: 2*(p+1) - E.order()
twist_order = 2 * (p + 1) - E.order()

print(f"[*] Twist Order: {twist_order}")

# --- Step 1: Find enough small factors ---
print("[*] Factoring twist order (partial)...")
factors_found = []
current_order = 1
remaining = twist_order

# Use trial division and ECM to find small factors
# We only need enough factors to cover 256 bits (~78 digits)
target_size = 1 << 258 

# Quick trial division first
for prime in primes(2, 10000):
    while remaining % prime == 0:
        factors_found.append(prime)
        current_order *= prime
        remaining //= prime

# Use ECM for larger factors if needed
if current_order < target_size:
    from sage.interfaces.ecm import ECM
    ecm = ECM()
    
    # Try to find factors until we have enough
    while current_order < target_size:
        print(f"[*] Current covered bits: {current_order.nbits()} / 256")
        # Try to find a factor of the remaining part
        res = ecm.factor(remaining)
        if isinstance(res, list): # ECM found factors
            for f in res:
                factors_found.append(f)
                current_order *= f
                remaining //= f
        elif isinstance(res, int): # ECM found one factor
             factors_found.append(res)
             current_order *= res
             remaining //= res
        
        # Safety break if we can't find more factors quickly
        if remaining == 1 or current_order >= target_size:
            break

print(f"[*] Factors found: {factors_found}")
print(f"[*] Subgroup size: {current_order.nbits()} bits")

if current_order < target_size:
    print("[!] Failed to find enough small factors. The twist might not be smooth enough.")
    exit()

# --- Step 2: Prepare the attack point ---
# Work on the Quadratic Twist
Twist = E.quadratic_twist()
g_twist = Twist.gen(0)

# We want a point P of order 'current_order'
# P = (Twist_Order // current_order) * g_twist
cofactor = twist_order // current_order
P = cofactor * g_twist

# Ensure P is not at infinity
while P == Twist(0):
    g_twist = Twist.random_point()
    P = cofactor * g_twist

# --- Step 3: Server Interaction ---
io = remote("localhost", 13417)
io.recvuntil(b'decimal format.\n')

# Send the point P (x-coordinate only)
payload = {"option": "get_pubkey", "x0": int(P[0])}
io.sendline(json.dumps(payload).encode())

# Receive public key (x-coordinate of d*P)
response = json.loads(io.recvline().decode())
if "error" in response:
    print("Error:", response["error"])
    exit()

pub_x = int(response["pubkey"])

# --- Step 4: Solve DLP ---
# Lift x-coordinate to a point on the Twist
# Note: There are two possible y-coordinates (+y and -y)
try:
    Q = Twist.lift_x(pub_x)
except ValueError:
    print("[!] The public point returned is not on the twist (math error?)")
    exit()

# Solve DLP: Q = d * P  =>  d = log_P(Q)
# Pohlig-Hellman is automatic in Sage for smooth orders
try:
    d = discrete_log(Q, P, operation="+", ord=current_order)
except:
    # If +y didn't work, try -y (though for x-only it shouldn't matter for the scalar magnitude)
    Q = -Q
    d = discrete_log(Q, P, operation="+", ord=current_order)

# Handle sign ambiguity
# The private key could be 'd' or 'current_order - d'
# Since the real key is 256 bits and 'current_order' might be larger,
# the correct key is the smaller one.
cands = [d, current_order - d]
key = min(cands)

print(f"[*] Recovered Private Key: {key}")

# --- Step 5: Submit Flag ---
payload = {"option": "get_flag", "privkey": int(key)}
io.sendline(json.dumps(payload).encode())
print(io.recvline().decode())