import re
from sage.all import *

# Cheap end-to-end validation on the REAL data, using the known flag.
# Confirms (without ever building the degree-~10^8 g(x)) that the true
#   x0 = m^{-C}  IS a root of the elimination -- i.e. the cubic + LLL-relation
# pipeline is correct and a full root-find WOULD recover m. Runs in ~1s.

C = 1337
def lcg(s, n): return (3*s + C) % n
p = 127673904854512340377644327691421646283087
q = 160733401619738555510927171021360193926549
N = p*q
m = Integer(int.from_bytes(b"HCMUS-CTF{E_L4_0_tHe:tH4NKs_Elita}", "big"))

def load_real(P):
    nums = [Integer(t) for t in re.findall(r'\d+', open("output.txt").read())]
    body = nums[1:]; sums, seeds = body[0::2], body[1::2]
    ks = []
    for i in range(len(seeds)-1):
        e1 = lcg(seeds[i], N); e2 = lcg(e1, N)
        if (3*e1 + C - e2)//N == 0:                       # k = 0 samples
            ks.append((Integer(e1 % (P-1)), Integer(sums[i+1] % P)))
    return ks

def find_relation(P, a):
    n = len(a); W = 2**(P.nbits()+8)
    M = Matrix(ZZ, n+2, n+2)
    for i in range(n):
        M[i,i] = 1; M[i,n+1] = W*a[i]
    M[n,n] = 1; M[n,n+1] = W*C
    M[n+1,n+1] = W*(P-1)
    rels = [tuple(int(r[j]) for j in range(n+1)) for r in M.LLL()
            if r[n+1] == 0 and any(r[j] for j in range(n+1))]
    rels.sort(key=lambda r: sum(c*c for c in r))
    return rels[0]

def check(P, which, n=6):
    Fp = GF(P)
    ks = load_real(P)
    a = [ai for ai, _ in ks[:n]]
    s = [ci for _, ci in ks[:n]]
    rel = find_relation(P, a); rc = list(rel[:n]); d = int(rel[n])

    x0 = Fp(m)**(-C)                                    # the global unknown, true value
    A  = [Fp(m)**int(ai) for ai in a]                   # true branch  A_i = m^{a_i}

    cubic_ok = all(A[i]**3 + x0*A[i] - Fp(s[i])*x0 == 0 for i in range(n))
    lhs = prod(A[i]**rc[i] for i in range(n))           # prod A_i^{rc_i}   (neg exps -> inverse)
    rel_ok = (lhs == x0**d)

    print(f"[mod {which}]  n={n}  mono-deg={sum(abs(v) for v in rc)+abs(d)}  d={d}")
    print(f"   cubic A^3 + x0*A - s*x0 == 0  for all {n} samples : {cubic_ok}")
    print(f"   relation  prod A^rc == x0^d                       : {rel_ok}")
    print(f"   => true x0 = m^-C is a root of g(x)               : {cubic_ok and rel_ok}\n")

if __name__ == '__main__':
    check(p, 'p')
    check(q, 'q')
