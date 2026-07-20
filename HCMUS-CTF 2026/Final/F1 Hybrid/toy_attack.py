"""
Validate the CONJUGACY attack on the toy period-2 cipher.

Key facts (period-2 keys k0 even rounds, k1 odd rounds, last round no-swap):
  E = swap o F^16          F  = rho_k1 o rho_k0
  D = swap o F'^16         F' = rho_k0 o rho_k1     (=> D == E with keys swapped)
  =>  E = rho_k0 o D o rho_k0      and      D = rho_k1 o E o rho_k1

Recover k0 from column relation:
  E((L,r0)).left == D((r0,L^K)).right ,  K = f(r0,k0)
A collision  EL(L) == DR(m)  suggests  K = L ^ m ; the true K is the mode.
Then k0 = Sinv( ROR(K) ) - r0.
"""
import random

HBITS = 12
HMASK = (1 << HBITS) - 1
ROT = 5

random.seed(2024)               # same toy sbox as toy_slide.py
_perm = list(range(1 << HBITS)); random.shuffle(_perm)
def S(x):  return _perm[x & HMASK]
Sinv = [0]*(1<<HBITS)
for x in range(1<<HBITS): Sinv[S(x)] = x
def rol(x): return ((x << ROT) | (x >> (HBITS - ROT))) & HMASK
def ror(x): return ((x >> ROT) | (x << (HBITS - ROT))) & HMASK
def f(R, k): return rol(S((R + k) & HMASK))

def rho(P, k):                  # one Feistel round WITH swap
    L, R = P
    return (R, L ^ f(R, k))

def round_fn(hi, lo, rk, is_enc, rnd):
    s = f(lo, rk) ^ hi
    if (is_enc and rnd == 31) or ((not is_enc) and rnd == 0):
        return (s, lo)
    return (lo, s)

def keyseq(k0, k1): return [k0 if r%2==0 else k1 for r in range(32)]

def E(P, k0, k1):
    rk = keyseq(k0,k1); hi,lo = P
    for r in range(32): hi,lo = round_fn(hi,lo,rk[r],True,r)
    return (hi,lo)
def Dd(C, k0, k1):
    rk = keyseq(k0,k1); hi,lo = C
    for r in reversed(range(32)): hi,lo = round_fn(hi,lo,rk[r],False,r)
    return (hi,lo)

def main():
    k0 = random.getrandbits(HBITS); k1 = random.getrandbits(HBITS)
    Ef = lambda P: E(P,k0,k1)
    Df = lambda C: Dd(C,k0,k1)
    print(f"true k0={k0:x} k1={k1:x}")

    # (b) verify conjugacy identities
    ok_b = all(Ef(x) == rho(Df(rho(x,k0)),k0)
               for x in [(random.getrandbits(HBITS),random.getrandbits(HBITS)) for _ in range(200)])
    ok_c = all(Df(x) == rho(Ef(rho(x,k1)),k1)
               for x in [(random.getrandbits(HBITS),random.getrandbits(HBITS)) for _ in range(200)])
    print("[id] E = rho_k0 o D o rho_k0 :", ok_b)
    print("[id] D = rho_k1 o E o rho_k1 :", ok_c)
    assert ok_b and ok_c

    # ---- recover k0 via column-collision (uses E and D oracles only) ----
    def recover(Eoracle, Doracle):
        r0 = 0
        T = 1 << (HBITS//2 + 2)     # data per column ~ 2^{n/4+2}
        Vset = random.sample(range(1<<HBITS), min(T, 1<<HBITS))
        # EL[L] = E((L,r0)).left ;  DR[m] = D((r0,m)).right
        EL = {L: Eoracle((L, r0))[0] for L in Vset}
        DR = {m: Doracle((r0, m))[1] for m in Vset}
        # collisions EL[L]==DR[m]  ->  candidate K = L^m
        from collections import Counter, defaultdict
        val2m = defaultdict(list)
        for m,v in DR.items(): val2m[v].append(m)
        cnt = Counter()
        for L,v in EL.items():
            for m in val2m.get(v, []):
                cnt[L ^ m] += 1
        K, c = cnt.most_common(1)[0]
        k0c = (Sinv[ror(K)] - r0) & HMASK
        return k0c, c, len(Vset)

    k0r, c0, n0 = recover(Ef, Df)
    k1r, c1, n1 = recover(Df, Ef)      # symmetric: D = rho_k1 o E o rho_k1
    print(f"recovered k0={k0r:x} (mode count {c0}, data {n0})  -> {'OK' if k0r==k0 else 'BAD'}")
    print(f"recovered k1={k1r:x} (mode count {c1}, data {n1})  -> {'OK' if k1r==k1 else 'BAD'}")

if __name__ == "__main__":
    main()
