"""
Validate slide-attack math on a small-scale clone of the F1 cipher.
Same structure: 32-round Feistel, period-2 keys (k0 even rounds, k1 odd),
last round no-swap, round f(R,k) = ROL(S(R+k), rot).  Small halves so we
can test exhaustively.
"""
import os, random

HBITS = 12               # half size in bits (block = 2*HBITS)
HMASK = (1 << HBITS) - 1
ROT = 5

# random bijective sbox on HBITS bits (toy)
random.seed(2024)
_perm = list(range(1 << HBITS))
random.shuffle(_perm)
def S(x):  return _perm[x & HMASK]

def rol(x, r):
    return ((x << r) | (x >> (HBITS - r))) & HMASK

def f(R, k):
    return rol(S((R + k) & HMASK), ROT)

def round_fn(hi, lo, rk, is_enc, rnd):
    s = f(lo, rk) ^ hi
    if (is_enc and rnd == 31) or ((not is_enc) and rnd == 0):
        return (s, lo)
    return (lo, s)

def keyseq(k0, k1):
    return [k0 if r % 2 == 0 else k1 for r in range(32)]

def E(P, k0, k1):
    rk = keyseq(k0, k1)
    hi, lo = P
    for r in range(32):
        hi, lo = round_fn(hi, lo, rk[r], True, r)
    return (hi, lo)

def D(C, k0, k1):
    rk = keyseq(k0, k1)
    hi, lo = C
    for r in reversed(range(32)):
        hi, lo = round_fn(hi, lo, rk[r], False, r)
    return (hi, lo)

# ---- F = 2-round step (k0 round then k1 round, both with swap) ----
def F2(P, k0, k1):
    L, R = P
    # round0 (k0, swap): (L,R)->(R, L^f(R,k0))
    X = L ^ f(R, k0)
    a, b = R, X
    # round1 (k1, swap): (a,b)->(b, a^f(b,k1))
    Y = a ^ f(b, k1)
    return (b, Y)            # = (X, R^f(X,k1))

def swap(P): return (P[1], P[0])

def main():
    k0 = random.getrandbits(HBITS)
    k1 = random.getrandbits(HBITS)
    print(f"true k0={k0:0{ (HBITS+3)//4 }x} k1={k1:0{ (HBITS+3)//4 }x}")

    # check E = swap o F2^16
    P = (random.getrandbits(HBITS), random.getrandbits(HBITS))
    acc = P
    for _ in range(16):
        acc = F2(acc, k0, k1)
    assert swap(acc) == E(P, k0, k1), "E != swap o F2^16"
    print("[ok] E = swap o F2^16  (clean period-2 structure)")

    # G(P) = swap(E(P)) = F2^16(P)
    def G(P): return swap(E(P, k0, k1))

    # Slide: slid pair (P1, P2=F2(P1)) satisfies G(P2) = F2(G(P1)).
    # Collect N known plaintexts, find a slid pair, recover keys.
    N = 1 << HBITS          # ~2^{n/2} where n=2*HBITS  (n/2 = HBITS)
    pts = set()
    while len(pts) < N:
        pts.add((random.getrandbits(HBITS), random.getrandbits(HBITS)))
    pts = list(pts)
    Gv = {P: G(P) for P in pts}

    # Detection (toy, O(N^2)): for each ordered pair (i,j) test if it's slid:
    #   P_j = F2(P_i)  AND  G(P_j) = F2(G(P_i))   for a single consistent (k0,k1).
    # We don't know keys; instead solve candidate k0 from the plaintext relation
    # and verify on ciphertext relation.
    # From P_j = F2(P_i): P_j.left = P_i.left ^ f(P_i.right, k0)
    #   -> f(P_i.right, k0) = P_i.left ^ P_j.left
    #   -> S(P_i.right + k0) = ROL^{-1}(P_i.left ^ P_j.left)
    #   -> k0 = S^{-1}( ror(...) ) - P_i.right
    Sinv = [0]*(1<<HBITS)
    for x in range(1<<HBITS): Sinv[S(x)] = x
    def ror(x, r): return ((x >> r) | (x << (HBITS - r))) & HMASK

    found = None
    Gset = Gv
    # index plaintexts by value for quick membership
    for i, Pi in enumerate(pts):
        Li, Ri = Pi
        Ci = Gset[Pi]
        for Pj in pts:
            Lj, Rj = Pj
            # candidate k0 from plaintext relation
            t = ror(Li ^ Lj, ROT)
            k0c = (Sinv[t] - Ri) & HMASK
            # verify full P_j == F2(P_i) under k0c needs k1 too; get k1 from 2nd coord:
            # P_j.right = P_i.right ^ f(P_j.left, k1)  -> f(Pj.left,k1)=Ri^Rj
            t2 = ror(Ri ^ Rj, ROT)
            k1c = (Sinv[t2] - Lj) & HMASK
            if F2(Pi, k0c, k1c) != Pj:
                continue
            # now verify ciphertext relation G(Pj) == F2(G(Pi)) under same keys
            Cj = Gset[Pj]
            if F2(Ci, k0c, k1c) == Cj:
                found = (k0c, k1c, Pi, Pj)
                break
        if found: break

    if found:
        k0c, k1c, Pi, Pj = found
        print(f"[recovered] k0={k0c:x} k1={k1c:x}  (slid pair {Pi}->{Pj})")
        print("MATCH" if (k0c, k1c) == (k0, k1) else "MISMATCH (but consistent eqns)")
    else:
        print("no slid pair found in", N, "texts (need ~2^{n/2} =", 1<<HBITS, ")")

if __name__ == "__main__":
    main()
