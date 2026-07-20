#!/usr/bin/env sage
# Stage 1: recover main secret S from CHALLENGE samples (C0 = a*S + r*e, m=0).
# Then compute s_aux = (S - OTP) mod q and analyze it (these are B_i*T+K_i mod q_aux).
import json

data = json.load(open("data.json"))
q   = Integer(data["q"])
n   = data["n"]                       # 32
otp = [Integer(x) for x in data["otp"]]
samples = data["samples"]
K = min(4, len(samples))              # number of samples to use in the lattice

def center(x):
    x = Integer(x) % q
    return x - q if x > q//2 else x

def negmat(a):
    # 32x32 negacyclic multiplication matrix for poly a, so (a*S)_k = sum_j M[k,j]*S_j
    M = matrix(ZZ, n, n)
    for k in range(n):
        for j in range(n):
            d = k - j
            M[k, j] = a[d] if d >= 0 else -a[d + n]
    return M

# ---- assemble stacked system  B*S + q*Z = c  (residual c-p = r*e small) ----
Bmat = matrix(ZZ, K*n, n)
cvec = []
M0 = None
c0_0 = None
for i in range(K):
    a  = [center(x) for x in samples[i]["c1"]]
    c0 = [Integer(x) % q for x in samples[i]["c0"]]
    Mi = negmat(a)
    if i == 0:
        M0, c0_0 = Mi, c0
    Bmat[i*n:(i+1)*n, :] = Mi
    cvec += c0
c = vector(ZZ, cvec)
m = K*n

# ---- CVP via Kannan embedding ----
W = 1
G = block_matrix(ZZ, [[q*identity_matrix(m)], [Bmat.transpose()]])   # (m+n) x m
E = matrix(ZZ, G.nrows() + 1, m + 1)
E[:G.nrows(), :m] = G
E[G.nrows(), :m] = c
E[G.nrows(), m]  = W

print("[*] LLL on %d x %d lattice ..." % (E.nrows(), E.ncols()))
L = E.LLL()

# find shortest row whose last coord is +-W
best = None
for row in L:
    if abs(row[-1]) == W:
        nr = sum(int(x)^2 for x in row[:-1])
        if best is None or nr < best[0]:
            best = (nr, row)
assert best is not None, "no embedding vector found"
row = best[1]
resid = vector(ZZ, [int(row[-1]) * int(row[i]) for i in range(m)])   # = r*e

print("[*] residual max abs =", max(abs(x) for x in resid), " r =", data["r"])
e_all = [x / Integer(data["r"]) for x in resid]
print("[*] residual divisible by r:", all(x in ZZ for x in e_all))
print("[*] error e (sample0):", [int(x) for x in e_all[:n]])

# ---- solve for S using sample 0 ----
R = Integers(q)
p0 = vector(R, [ (c0_0[k] - resid[k]) for k in range(n) ])
S = M0.change_ring(R).solve_right(p0)
S = [Integer(x) for x in S]
print("[*] S bit-lengths:", sorted(set(x.nbits() for x in S)))

# verify against ALL collected samples
ok = True
for i in range(len(samples)):
    a  = [center(x) for x in samples[i]["c1"]]
    Mi = negmat(a)
    pred = Mi * vector(ZZ, S)
    for k in range(n):
        d = Integer(int(samples[i]["c0"][k]) - int(pred[k])) % q
        d = d - q if d > q//2 else d
        if abs(d) > 10^9:               # should be ~ r*e
            ok = False
print("[*] all-sample consistency (residual small):", ok)

# ---- Stage 2 input: s_aux = (S - OTP) mod q ----
s_aux = [ (S[i] - otp[i]) % q for i in range(n) ]
bl = sorted((x.nbits(), i) for i, x in enumerate(s_aux))
print("\n[*] s_aux bit-length distribution:")
from collections import Counter
print("   ", Counter(x.nbits() for x in s_aux))
small = [x for x in s_aux if x.nbits() <= 200]
large = [x for x in s_aux if x.nbits() > 200]
print("[*] #small(<=200b):", len(small), " #large(>200b):", len(large))
if small:
    print("    small max nbits:", max(x.nbits() for x in small))
if large:
    print("    large min:", min(large))
    print("    large max:", max(large))
    print("    q - large_max =", q - max(large), " (nbits", (q-max(large)).nbits(), ")")
    print("    q - large_min =", q - min(large), " (nbits", (q-min(large)).nbits(), ")")

json.dump({"S": [int(x) for x in S], "s_aux": [int(x) for x in s_aux]},
          open("stage1_out.json", "w"))
print("\n[*] wrote stage1_out.json")
