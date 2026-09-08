from sage.all import *
from pwn import remote
import json

# --- 1. Setup Parameters ---
p = 13407807929942597099574024998205846127479365820592393377723561443721764030029777567070168776296793595356747829017949996650141749605031603191442486002224009
a = -3
b = 152961

# The True Trapdoor: p = q^2
q = 2**256 - 189

print("[*] Setting up field over GF(q)...")
F = GF(q)
E = EllipticCurve(F, [a, b])
N = E.order()
print(f"[+] Base order of curve over GF(q): {N}")

# --- 2. Generate a valid x0 ---
print("[*] Generating a valid base point...")
x0_Fq = F.random_element()
# Ensure x0 is a valid x-coordinate on the original curve
while not (x0_Fq**3 + a*x0_Fq + b).is_square():
    x0_Fq = F.random_element()

x0 = int(x0_Fq)
print(f"[+] Chosen x0: {x0}")

# --- 3. Interact with Server ---
io = remote("socket.cryptohack.org", 13417)
io.recvuntil(b'decimal format.\n')

payload = {"option": "get_pubkey", 'x0': x0}
io.sendline(json.dumps(payload).encode())

response = json.loads(io.recvline().decode())
if "error" in response:
    print("[-] Error:", response)
    exit()

# The server returns the key computed modulo p (q^2)
res_x_mod_p = Integer(response["pubkey"])
print(f"[+] Received pubkey x (mod q^2): {res_x_mod_p}")

# --- 4. The p-adic Lift (Elliptic Curve Paillier Trapdoor) ---
print("[*] Lifting to p-adics Qp(q, precision=2)...")
Qq = Qp(q, 2)
Eq = EllipticCurve(Qq, [a, b])

try:
    P_padic = Eq.lift_x(Qq(x0))
    Q_padic = Eq.lift_x(Qq(res_x_mod_p))
except ValueError as e:
    print(f"[-] Failed to lift to p-adics: {e}")
    exit()

print("[*] Multiplying points by N to project into the q-torsion subgroup E_1...")
P1 = N * P_padic
Q1 = N * Q_padic

# Extract the coordinates in Qq
x_P, y_P = P1.xy()
x_Q, y_Q = Q1.xy()

# Calculate the formal group logarithm (-x/y)
log_P = - x_P / y_P
log_Q = - x_Q / y_Q

print("[*] Solving Discrete Log via Formal Logarithm division...")
d_recovered = Integer(log_Q / log_P) % q

# --- 5. Submit Flag ---
# Because x-coordinate arithmetic loses the sign of y, Q could be +dP or -dP.
candidates = [d_recovered, (-d_recovered) % q]
d_real = min(candidates)

print(f"[*] Recovered true private key: {d_real}")

payload = {"option": "get_flag", "privkey": int(d_real)}
io.sendline(json.dumps(payload).encode())
res = io.recvline().decode()
print(res)

io.close()