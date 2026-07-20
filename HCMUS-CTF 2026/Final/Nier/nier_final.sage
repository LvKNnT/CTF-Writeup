#!/usr/bin/env sage
# =====================================================================================
# nier_final.sage  --  complete, self-testing NieR step-3 solver.
#
#   factored N (p,q known) -> LLL a short relation  Sum c_i a_i + C d = 0 (mod P-1)
#   -> composed-product elimination  g(x)  with  g(m^{-C}) = 0
#   -> x^P mod g + gcd(g, x^P - x)  via python-flint  (LEAN: this is the usual OOM point)
#   -> GF(P) roots -> candidates for m mod P
#   -> keep the candidate(s) that REPRODUCE the sample sums mod P   (definitive filter,
#      replaces the chi3 branch-guessing: only the true m mod P passes)
#   -> CRT (m mod p, m mod q) -> decode flag.
#
# The relation is chosen to MINIMISE  deg g = 3^{support-1}*(mono-deg+2|d|)  (small support,
# balanced pos/neg), so the elimination is as small as this method allows (~2^26-2^28 at 137b).
#
# USAGE
#   sage nier_final.sage selftest [bits] [n]   # prove the WHOLE chain (recovers m) on toy params
#   sage nier_final.sage p [n]                 # m mod p -> cands_p.txt   (n default 8)
#   sage nier_final.sage q [n]                 # m mod q -> cands_q.txt
#   sage nier_final.sage combine               # CRT the two files -> flag
#   sage nier_final.sage all [n]               # p, q, combine in one shot
#
# MEMORY: g is ~ deg*ceil(P.nbits()/8) bytes (~1.4 GB at n=8). The flint root-find peaks
# ~3-5x that. If it still OOMs at the RESULTANT (before root-find), that build is the wall
# and needs a bigger box (see profile_recover.sage to confirm where it dies).
# =====================================================================================

import re, sys, time, gc
from sage.all import *

C = 1337
def lcg(s, n): return (3*s + C) % n

p = Integer(127673904854512340377644327691421646283087)
q = Integer(160733401619738555510927171021360193926549)
N = p*q
FLAG_PREFIX = b"HCMUS"

def log(*a): print(*a, flush=True)

# ------------------------------------------------------------------ data / lattice
def load_real(P):
    assert P in (p, q) and p*q == N
    nums = [Integer(t) for t in re.findall(r'\d+', open("output.txt").read())]
    body = nums[1:]; sums, seeds = body[0::2], body[1::2]
    ks = []
    for i in range(len(seeds)-1):
        e1 = lcg(seeds[i], N); e2 = lcg(e1, N)
        if (3*e1 + C - e2)//N == 0:                     # k=0 samples (clean cubic)
            ks.append((Integer(e1 % (P-1)), Integer(sums[i+1] % P)))
    return ks

def best_relation(P, a):
    """Among short relations Sum c_i a_i + C d = 0 (mod P-1), return the one minimising
       the predicted deg g = 3^{support-1}*(mono-deg + 2|d|)  (favours small, balanced support)."""
    n = len(a); W = 2**(P.nbits()+8)
    M = Matrix(ZZ, n+2, n+2)
    for i in range(n):
        M[i, i] = 1; M[i, n+1] = W*a[i]
    M[n, n] = 1; M[n, n+1] = W*C
    M[n+1, n+1] = W*(P-1)
    best = None                                          # (work, degF, rc, d)
    for r in M.LLL():
        if r[n+1] != 0:
            continue
        rc = [int(r[j]) for j in range(n)]; d = int(r[n])
        if not any(rc) and d == 0:
            continue
        npos = sum(1 for v in rc if v > 0); nneg = sum(1 for v in rc if v < 0)
        support = npos + nneg
        monodeg = sum(abs(v) for v in rc) + abs(d)
        degF = 3**(support-1) * (monodeg + 2*abs(d))
        work = degF * (3**(2*npos) + 3**(2*nneg))        # ~ #points * per-point cost; favours 3/3
        if best is None or work < best[0]:
            best = (work, degF, rc, d)
    return best[1], best[2], best[3]                     # (deg F estimate, rc, d)

# ------------------------------------------------------------------ g(x) by INTERPOLATION
# Author's construction:  F(x) = Res_Z(P_+(Z), P_-(Z)), where each side's polynomial has the
# 3^{|pos|}/3^{|neg|} root-PRODUCTS  prod A_i^{c_i}  as its roots.  Taking that resultant
# SYMBOLICALLY over GF(P)[x] is the 150 GB step (a degree-~10^8 subresultant chain).  Instead
# we EVALUATE F at numeric x = v (each a tiny degree-27 x degree-27 numeric resultant) and
# INTERPOLATE ("noi suy") -> bounded memory (~O(deg F) for the point/value arrays only).
def _F_at(Fp, Z, cpos, spos, cneg, sneg, d, v):
    """Numeric F(v) = Res_Z(P_+(v), P_-(v)).  All polynomials here are degree <= 3^k over GF(P)."""
    def comp(cs, svals):                                 # monic Z-poly whose roots are prod r_i^{c_i}
        Ntot = 3**len(cs)
        Ps = [Fp(0)] + [Fp(1)]*Ntot                      # Ps[k] = prod_i p_{c_i k}(cubic_i)
        for c, sv in zip(cs, svals):
            z = PolynomialRing(Fp, 'z').gen()
            Q = z.parent().quotient(z**3 + v*z - sv*v)
            ze = Q(z)**int(c); cur = Q(1)
            for k in range(1, Ntot+1):
                cur = cur * ze
                co = cur.lift().list(); co += [Fp(0)]*(3 - len(co))
                Ps[k] *= (3*co[0] - 2*co[2]*v)           # p_{ck} = 3 alpha - 2 gamma v
        e = [Fp(1)] + [Fp(0)]*Ntot                       # Newton -> elementary symmetric
        for k in range(1, Ntot+1):
            acc = Fp(0)
            for j in range(1, k+1):
                acc += (-1)**(j-1) * e[k-j] * Ps[j]
            e[k] = acc / Fp(k)
        return sum((-1)**k * e[k] * Z**(Ntot-k) for k in range(Ntot+1))
    Pp = comp(cpos, spos); Pm = comp(cneg, sneg)
    Np, Nm = Pp.degree(), Pm.degree()
    if d >= 0:                                           # scale P_- roots by v^d
        vd = v**d;  Pm = sum(Pm[k]*vd**(Nm-k)*Z**k for k in range(Nm+1))
    else:                                                # scale P_+ roots by v^{-d}
        ve = v**(-d); Pp = sum(Pp[k]*ve**(Np-k)*Z**k for k in range(Np+1))
    return Pp.resultant(Pm)

def build_g(P, a, s, rc, d):
    Fp = GF(P)
    pos = [i for i in range(len(rc)) if rc[i] > 0]
    neg = [i for i in range(len(rc)) if rc[i] < 0]
    cpos = [rc[i] for i in pos]; spos = [s[i] for i in pos]
    cneg = [-rc[i] for i in neg]; sneg = [s[i] for i in neg]
    Sp, Sn = sum(cpos), sum(cneg)
    Dp = 3**(len(pos)-1) * Sp if pos else 0
    Dn = (3**(len(neg)-1) * Sn if neg else 0) + (d if d > 0 else 0) * 3**len(neg)
    Du = 3**len(pos) * Dn + 3**len(neg) * Dp             # upper bound on deg F
    npts = int(Du) + 2
    T = PolynomialRing(Fp, 'x')
    Z = PolynomialRing(Fp, 'Z').gen()
    log(f"    interpolation build: deg F <= {Du}, sampling {npts} points (bounded memory)")
    if npts > 5_000_000:
        log(f"    !! {npts} points: pure-Sage eval/interp is too slow at this scale.")
        log(f"       This is correct + memory-bounded, but the real 137-bit run needs the")
        log(f"       per-point kernel + interpolation + root-find in flint/C (author's ~2 h).")
    t = time.time()
    xs = [Fp(v) for v in range(1, npts+1)]
    ys = [_F_at(Fp, Z, cpos, spos, cneg, sneg, d, xv) for xv in xs]
    log(f"    evaluated {npts} points ({time.time()-t:.1f}s)")
    t = time.time()
    g = T.lagrange_polynomial(list(zip(xs, ys)))         # small D only; use flint interp for big D
    if g != 0 and g.valuation() > 0:
        g = g >> g.valuation()                           # drop spurious x=0 factor
    log(f"    interpolated g deg {g.degree()} ({time.time()-t:.1f}s)")
    return g

# ------------------------------------------------------------------ GF(P) roots (flint, lean)
def gfp_roots(g, P):
    """Roots of g in GF(P). Does x^P mod g + gcd(g, x^P - x) in python-flint if available
       (much leaner than Sage on huge g), else falls back to Sage."""
    coeffs = [int(c) for c in g.list()]
    t = time.time()
    try:
        from flint import fmpz_mod_poly_ctx
        R = fmpz_mod_poly_ctx(int(P))
        gf = R(coeffs)
        base = R([0, 1]) % gf
        res = R([1]); e = int(P)
        while e > 0:                                     # x^P mod g, square-and-multiply
            if e & 1: res = (res * base) % gf
            base = (base * base) % gf
            e >>= 1
        gg = gf.gcd((res - R([0, 1])) % gf)              # product of (x - r), r in GF(P)
        log(f"    flint x^P mod g + gcd -> split deg {gg.degree()} ({time.time()-t:.1f}s)")
        roots = []
        for fac, _ in gg.factor():
            if fac.degree() == 1:
                c = [int(t2) for t2 in fac.coeffs()]     # c0 + c1 x
                roots.append(Integer((-c[0]) * pow(c[1], -1, int(P)) % int(P)))
        return roots
    except Exception as ex:
        log(f"    [flint unavailable/failed: {ex}] -> Sage root-find")
        T = g.parent(); x = T.gen()
        gg = g.gcd(pow(x, P, g) - x)
        log(f"    Sage x^P mod g + gcd -> split deg {gg.degree()} ({time.time()-t:.1f}s)")
        return [Integer(r) for r, _ in gg.roots() if r != 0]

# ------------------------------------------------------------------ recover m mod P
def reproduces(P, m_p, samples, checks=8):
    """True iff candidate m_p reproduces the k=0 sample sums mod P (definitive filter)."""
    Pi = int(P); mi = int(m_p) % Pi
    for a_i, S_i in samples[:checks]:
        b_i = int((3*a_i + C) % (P-1))
        if (pow(mi, int(a_i), Pi) + pow(mi, b_i, Pi)) % Pi != int(S_i) % Pi:
            return False
    return True

def recover_mod_P(P, samples, n, m_true=None):
    a = [ai for ai, _ in samples[:n]]
    s = [GF(P)(ci) for _, ci in samples[:n]]
    pred, rc, d = best_relation(P, a)
    support = sum(1 for v in rc if v != 0)
    log(f"    rel support={support} mono-deg={sum(abs(v) for v in rc)+abs(d)} d={d}"
        f"  predicted deg g ~ {float(pred):.3e}")
    g = build_g(P, a, s, rc, d)
    roots = gfp_roots(g, P)
    inv = inverse_mod(C, P-1)
    cands = {Integer(pow(int(r), (-inv) % (P-1), P)) for r in roots if r != 0}
    good = sorted(c for c in cands if reproduces(P, c, samples))
    msg = f"    {len(cands)} roots -> {len(good)} verified candidate(s)"
    if m_true is not None:
        msg += f"  [true recovered: {Integer(m_true % P) in good}]"
    log(msg)
    return good

# ------------------------------------------------------------------ modes
def selftest(bits, n):
    while True:
        pp = random_prime(2**bits, lbound=2**(bits-1))
        qq = random_prime(2**bits, lbound=2**(bits-1))
        if pp != qq and gcd(C, pp-1) == 1:
            break
    NN = pp*qq; m = randint(2, NN-1); ks = []
    while len(ks) < n*4:
        ss = randint(731, NN); e1 = lcg(ss, NN); e2 = lcg(e1, NN)
        if (3*e1 + C - e2)//NN == 0:
            ks.append((Integer(e1 % (pp-1)), Integer((pow(m, e1, pp) + pow(m, e2, pp)) % pp)))
    log(f"[selftest bits={bits} n={n}]  m mod p = {m % pp}")
    good = recover_mod_P(pp, ks, n, m_true=Integer(m % pp))
    ok = Integer(m % pp) in good
    log(f"  => {'PASS' if ok else 'FAIL'}\n")
    return ok

def run_prime(which, n):
    P = p if which == 'p' else q
    t = time.time()
    good = recover_mod_P(P, load_real(P), n)
    open(f"cands_{which}.txt", "w").write("\n".join(str(c) for c in good))
    log(f"[{which}] {len(good)} candidate(s) -> cands_{which}.txt ({time.time()-t:.1f}s)")
    return good

def prep(which, n):
    """Emit relation_<which>.txt for the flint engine (nier_flint.py). Searches candidate
       supports and keeps the relation with the SMALLEST predicted deg F (= phase-2 size).
       deg F is minimised around support 8; small support (6) is fast in phase 1 but the
       deg F ~4e8 blows phase-2 memory, so we trade a slower phase 1 for a feasible phase 2."""
    P = p if which == 'p' else q
    samples = load_real(P)
    cand = [n] if n else [6, 7, 8, 9, 10]
    best = None
    for nn in cand:
        a = [ai for ai, _ in samples[:nn]]
        pred, rc, d = best_relation(P, a)
        pos = [i for i in range(len(rc)) if rc[i] > 0]
        neg = [i for i in range(len(rc)) if rc[i] < 0]
        log(f"    n={nn}: support={len(pos)+len(neg)} |pos|={len(pos)} |neg|={len(neg)} "
            f"d={d}  predicted deg F ~ {float(pred):.3e}")
        if best is None or pred < best[0]:
            best = (pred, rc, d, nn)
    pred, rc, d, nn = best
    s = [GF(P)(ci) for _, ci in samples[:nn]]
    pos = [i for i in range(len(rc)) if rc[i] > 0]
    neg = [i for i in range(len(rc)) if rc[i] < 0]
    with open(f"relation_{which}.txt", "w") as f:
        f.write(f"P {P}\nC {C}\nd {d}\n")
        for i in pos:
            f.write(f"pos {rc[i]} {int(s[i])}\n")
        for i in neg:
            f.write(f"neg {-rc[i]} {int(s[i])}\n")
        for ai, Si in samples[:16]:                      # for reproduces()-style filtering
            f.write(f"chk {int(ai)} {int(Si)}\n")
    log(f"[{which}] CHOSE n={nn}: |pos|={len(pos)} |neg|={len(neg)} d={d}  "
        f"deg F ~ {float(pred):.3e}  -> relation_{which}.txt")

def prep2(which, off=16, n=8):
    """Emit relation2_<which>.txt -- a SECOND relation from a different sample window (so its
       spurious roots differ from relation #1), support ~8 so deg F2 (~8e7) stays small and the
       gcd(F1,F2) is cheap. Used by the two-relation GCD path in nier_flint.py (`gcd` mode)."""
    P = p if which == 'p' else q
    samples = load_real(P)
    idx = list(range(off, off + n))
    a = [samples[j][0] for j in idx]
    s = [GF(P)(samples[j][1]) for j in idx]
    pred, rc, d = best_relation(P, a)
    pos = [i for i in range(len(rc)) if rc[i] > 0]
    neg = [i for i in range(len(rc)) if rc[i] < 0]
    with open(f"relation2_{which}.txt", "w") as f:
        f.write(f"P {P}\nC {C}\nd {d}\n")
        for i in pos:
            f.write(f"pos {rc[i]} {int(s[i])}\n")
        for i in neg:
            f.write(f"neg {-rc[i]} {int(s[i])}\n")
        for ai, Si in samples[:16]:
            f.write(f"chk {int(ai)} {int(Si)}\n")
    log(f"[{which}] relation2 (samples[{off}:{off+n}]): |pos|={len(pos)} |neg|={len(neg)} d={d}  "
        f"deg F2 ~ {float(pred):.3e}  -> relation2_{which}.txt")

def combine():
    cp = [Integer(t) for t in open("cands_p.txt").read().split()]
    cq = [Integer(t) for t in open("cands_q.txt").read().split()]
    log(f"combine: {len(cp)} x {len(cq)} CRT pairs")
    for mp in cp:
        for mq in cq:
            m = Integer(crt([mp, mq], [p, q])) % N
            b = int(m).to_bytes((int(m).bit_length()+7)//8, 'big')
            if b.startswith(FLAG_PREFIX):
                log("FLAG: " + b.decode('latin1', 'replace'))
                return b
    log("no flag among CRT pairs -- increase n or gather more candidates")

if __name__ == '__main__':
    args = sys.argv[1:]
    mode = args[0] if args else 'selftest'
    if mode == 'selftest':
        bits = int(args[1]) if len(args) > 1 else 28
        n = int(args[2]) if len(args) > 2 else 5
        selftest(bits, n)
    elif mode in ('p', 'q'):
        run_prime(mode, int(args[1]) if len(args) > 1 else 8)
    elif mode == 'prep':
        n = int(args[2]) if len(args) > 2 else 6         # n=6 -> author's 27-products-per-side
        which = args[1] if len(args) > 1 else 'p'
        prep(which, n)
    elif mode == 'prep2':                                # 2nd relation for the gcd path
        which = args[1] if len(args) > 1 else 'p'
        off = int(args[2]) if len(args) > 2 else 16
        prep2(which, off)
    elif mode == 'combine':
        combine()
    elif mode == 'all':
        n = int(args[1]) if len(args) > 1 else 8
        run_prime('p', n); run_prime('q', n); combine()
    else:
        log(__doc__ if __doc__ else "see header for usage")
