#!/usr/bin/env python3
# =====================================================================================
# nier_flint.py -- real-scale engine for NieR step-3, memory-bounded + parallel.
#
# Implements the author's construction directly:
#     F(x) = Res_Z( P_+(Z), P_-(Z) )        (the 27-per-side composed-product resultant)
# but built by EVALUATION + INTERPOLATION ("noi suy") instead of a symbolic resultant, so
# memory stays O(deg F) instead of the ~150 GB subresultant chain.
#
#   PHASE 1 (eval, the long part -- PARALLEL, pure gmpy2, tiny memory/point):
#       F(v) at v = 1..deg F+1.  Per point: two composed-product polys (deg 3^|pos|,3^|neg|)
#       via power sums + Newton, then a resultant -- all small (<=81) polys over GF(P).
#   PHASE 2 (interpolate F from the (v,F(v)) pairs -- flint subproduct tree).
#   PHASE 3 (root-find: gcd(F, x^P - x) via flint -> x0 -> m mod P; keep those that
#            reproduce the sample sums).  CRT p,q -> flag.
#
# REQUIRES: gmpy2 (phase 1) and python-flint (phases 2-3).
#
# USAGE
#   python nier_flint.py selftest [bits]        # builds a small instance (incl. its own LLL),
#                                               # runs ALL phases, asserts m recovered.
#   sage nier_final.sage prep p 6               # emit relation_p.txt  (n=6 -> author's 27/side)
#   sage nier_final.sage prep q 6               # emit relation_q.txt
#   python nier_flint.py run p [procs]          # -> cands_p.txt
#   python nier_flint.py run q [procs]          # -> cands_q.txt
#   python nier_flint.py combine                # CRT -> flag   (p,q factors are hardcoded)
#
# SCALE NOTE: at 137 bits deg F ~1e8, so phase 1 is ~1e8 point-evals (parallelise across
# cores) and phase 2's subproduct tree is ~tens of GB. Both are bounded -- no 150 GB wall.
# Validate correctness with `selftest` FIRST; that exercises every line at small size.
# =====================================================================================

import sys, os, time, re, gc
from multiprocessing import Pool

try:
    import gmpy2
    from gmpy2 import mpz, powmod, invert
except ImportError:
    sys.exit("need gmpy2:  pip install gmpy2")

C = 1337
P_REAL = 127673904854512340377644327691421646283087
Q_REAL = 160733401619738555510927171021360193926549
N_REAL = P_REAL * Q_REAL


# --------------------------------------------------------------- GF(P) polynomials (mpz lists, low->high)
def _trim(a, P):
    a = [x % P for x in a]
    while a and a[-1] == 0:
        a.pop()
    return a

def polymod(a, b, P):
    """remainder of a mod b over GF(P); a,b low->high coeff lists (b != 0)."""
    a = [x % P for x in a]
    db = len(b) - 1
    invlb = invert(b[-1] % P, P)
    while len(a) - 1 >= db and len(a) > 0:
        if a[-1] % P == 0:
            a.pop(); continue
        coef = (a[-1] * invlb) % P
        top = len(a) - 1
        for j in range(db + 1):
            a[top - db + j] = (a[top - db + j] - coef * b[j]) % P
        a.pop()
    return a

def resultant(a, b, P):
    """Res(a,b) over GF(P), a,b low->high. Field recursion:
       Res(a,b) = (-1)^{deg a*deg b} lc(b)^{deg a-deg r} Res(b,r),  r=a mod b."""
    a = _trim(a[:], P); b = _trim(b[:], P)
    if not a or not b:
        return mpz(0)
    res = mpz(1)
    while len(b) - 1 >= 1:
        m, n = len(a) - 1, len(b) - 1
        r = _trim(polymod(a[:], b, P), P)
        if not r:
            return mpz(0)                                  # b | a  -> common root
        dr = len(r) - 1
        if (m * n) & 1:
            res = (-res) % P
        res = (res * powmod(b[-1] % P, m - dr, P)) % P
        a, b = b, r
    m = len(a) - 1
    return (res * powmod(b[0] % P, m, P)) % P


# --------------------------------------------------------------- cubic quotient GF(P)[z]/(z^3+v z - Sv)
def _cmul(x, y, v, Sv, P):
    a0, a1, a2 = x; b0, b1, b2 = y
    c0 = a0*b0; c1 = a0*b1 + a1*b0; c2 = a0*b2 + a1*b1 + a2*b0
    c3 = a1*b2 + a2*b1; c4 = a2*b2
    r0 = (c0 + c3*Sv) % P                                   # z^3 = Sv - v z
    r1 = (c1 - c3*v + c4*Sv) % P                            # z^4 = Sv z - v z^2
    r2 = (c2 - c4*v) % P
    return (r0, r1, r2)

def _cpow(base, e, v, Sv, P):
    res = (mpz(1), mpz(0), mpz(0))
    while e > 0:
        if e & 1:
            res = _cmul(res, base, v, Sv, P)
        base = _cmul(base, base, v, Sv, P); e >>= 1
    return res


def side_poly(cubics, v, P, Ntot, invk):
    """monic deg-Ntot poly (low->high) whose roots are the products prod_i r_i^{c_i},
       r_i over the roots of cubic_i = z^3 + v z - S_i v.  Built from power sums + Newton.
       Composed (multiplicative) product: p_k = prod_i p_{c_i k}(cubic_i).
       invk[k] = k^{-1} mod P precomputed once (Newton needs it every point otherwise)."""
    prodPs = [mpz(1)] * (Ntot + 1)                          # prodPs[k], k=0..Ntot (prodPs[0] unused)
    for (c, S) in cubics:
        Sv = (S * v) % P
        ze = _cpow((mpz(0), mpz(1), mpz(0)), c, v, Sv, P)   # z^c mod cubic
        cur = (mpz(1), mpz(0), mpz(0))
        for k in range(1, Ntot + 1):
            cur = _cmul(cur, ze, v, Sv, P)                  # z^{c k} mod cubic
            pk = (3*cur[0] - 2*v*cur[2]) % P                # power sum p_{ck} = 3 a0 - 2 v a2
            prodPs[k] = (prodPs[k] * pk) % P
    e = [mpz(1)] + [mpz(0)] * Ntot                          # Newton: elementary symmetric
    for k in range(1, Ntot + 1):
        acc = mpz(0)
        for j in range(1, k + 1):
            term = (e[k - j] * prodPs[j]) % P
            acc = (acc - term) if ((j - 1) & 1) else (acc + term)
        e[k] = (acc % P) * invk[k] % P
    coeffs = [mpz(0)] * (Ntot + 1)                          # poly = sum (-1)^k e[k] Z^{Ntot-k}
    for k in range(Ntot + 1):
        val = e[k] % P
        coeffs[Ntot - k] = (-val) % P if (k & 1) else val
    return coeffs                                           # low->high, monic


# --------------------------------------------------------------- per-point F(v)  (worker globals via _init)
_G = {}
def _init(P, cpos, cneg, d, Npos, Nneg):
    Pm = mpz(P)
    invk = [mpz(0)] + [invert(mpz(k), Pm) for k in range(1, max(Npos, Nneg) + 1)]  # once, not per point
    _G.update(P=Pm, cpos=[(mpz(c), mpz(S)) for c, S in cpos],
              cneg=[(mpz(c), mpz(S)) for c, S in cneg], d=d, Npos=Npos, Nneg=Nneg, invk=invk)

def _scale_roots(coeffs, vd, P):
    """roots *= vd:  poly(Z)=sum a_k Z^k -> sum a_k vd^{deg-k} Z^k."""
    deg = len(coeffs) - 1
    pw = [mpz(1)] * (deg + 1)
    for k in range(1, deg + 1):
        pw[k] = (pw[k - 1] * vd) % P
    return [(coeffs[k] * pw[deg - k]) % P for k in range(deg + 1)]

def F_at(v):
    P = _G["P"]; d = _G["d"]; v = mpz(v) % P; invk = _G["invk"]
    Pp = side_poly(_G["cpos"], v, P, _G["Npos"], invk)
    Pm = side_poly(_G["cneg"], v, P, _G["Nneg"], invk)
    if d >= 0:
        Pm = _scale_roots(Pm, powmod(v, d, P), P)           # P_- roots scaled by v^d
    else:
        Pp = _scale_roots(Pp, powmod(v, -d, P), P)          # P_+ roots scaled by v^{-d}
    return int(resultant(Pp, Pm, P))

_KERN = None
def _kinit(P, cpos, cneg, d, Npos, Nneg):
    global _KERN
    import nier_kernel
    _KERN = nier_kernel.NierKernel(str(P), cpos, cneg, d, Npos, Nneg)
def _kworker(rng):
    return _KERN.eval_range(rng[0], rng[1])

def _have_kernel():
    try:
        import nier_kernel  # noqa: F401
        return True
    except Exception:
        return False

def eval_points(P, cpos, cneg, d, Npos, Nneg, npts, procs):
    xs = list(range(1, npts + 1))
    ys = [0] * npts
    t0 = time.time(); last = [t0]
    def progress(done):
        now = time.time()
        if now - last[0] >= 15 or done >= npts:
            rate = done / max(now - t0, 1e-9)
            eta = (npts - done) / rate / 3600 if rate else 0
            print(f"      eval {done}/{npts} ({100*done/npts:5.1f}%)  {rate:9.0f} pts/s  "
                  f"ETA {eta:5.2f} h", flush=True)
            last[0] = now

    if _have_kernel():                                              # C-speed path
        chunk = max(1000, min(500000, npts // (max(procs, 1) * 16) + 1))
        ranges = [(i + 1, min(i + 1 + chunk, npts + 1)) for i in range(0, npts, chunk)]
        pos = 0
        if procs and procs > 1:
            with Pool(procs, initializer=_kinit, initargs=(P, cpos, cneg, d, Npos, Nneg)) as pool:
                for res in pool.imap(_kworker, ranges):
                    ys[pos:pos + len(res)] = res; pos += len(res); progress(pos)
        else:
            _kinit(P, cpos, cneg, d, Npos, Nneg)
            for r in ranges:
                res = _kworker(r); ys[pos:pos + len(res)] = res; pos += len(res); progress(pos)
        print(f"    phase1 (C kernel): {npts} points ({time.time()-t0:.1f}s)", flush=True)
        return xs, ys

    if procs and procs > 1:                                        # pure-gmpy2 fallback
        with Pool(procs, initializer=_init, initargs=(P, cpos, cneg, d, Npos, Nneg)) as pool:
            for i, val in enumerate(pool.imap(F_at, xs, chunksize=max(1, npts // (procs * 128)))):
                ys[i] = val
                if (i & 0xFFFF) == 0:
                    progress(i + 1)
    else:
        _init(P, cpos, cneg, d, Npos, Nneg)
        for i, v in enumerate(xs):
            ys[i] = F_at(v)
            if (i & 0xFFFF) == 0:
                progress(i + 1)
    print(f"    phase1 (gmpy2): evaluated {npts} points ({time.time()-t0:.1f}s)", flush=True)
    return xs, ys


# --------------------------------------------------------------- flint: interpolate + root-find
def _ctx(P):
    import flint
    try:
        return flint.fmpz_mod_poly_ctx(P)
    except Exception:
        return flint.fmpz_mod_poly_ctx(flint.fmpz_mod_ctx(P))

def _coeffs(poly):
    try:
        return [int(c) for c in poly.coeffs()]
    except Exception:
        return [int(c) for c in list(poly)]

def interpolate_file(P, path, n):
    """Interpolate F with F(i) = (18-byte value #i in `path`) at CONSECUTIVE points i=1..n.
       Streams the evaluations from disk (no O(n) ys list) and uses a RUNNING Lagrange
       denominator M'(i+1) = M'(i)*(-i)/(n-i) (no O(n) factorial table), so the only O(n)
       object is one subproduct-tree level -- combined bottom-up, freeing each lower level.
       Prints per-level progress."""
    ctx = _ctx(P); Pm = mpz(P); t0 = time.time()
    print(f"    phase2: interpolating deg <= {n-1} (streaming from {path})", flush=True)
    fac = mpz(1)                                                          # M'(1) = (-1)^{n-1} (n-1)!
    for k in range(1, n):
        fac = fac * k % P
    if (n - 1) & 1:
        fac = (-fac) % P
    minv = invert(fac % P, Pm)                                           # inv(M'(i)), running
    fh = open(path, "rb")
    def take(i):                                                         # value #i / M'(i); call in order
        y = mpz(int.from_bytes(fh.read(18), "big"))
        return int(y * minv % P)
    def adv(i):                                                          # minv: i -> i+1
        return minv * (n - i) % P * ((-invert(mpz(i), Pm)) % P) % P
    Mlev = []; Vlev = []
    i = 1; step = 1 << 22
    while i + 1 <= n:
        cj = take(i); minv = adv(i)
        cj1 = take(i + 1); minv = adv(i + 1)
        Mlev.append(ctx([(-i) % P, 1]) * ctx([(-(i + 1)) % P, 1]))
        Vlev.append(ctx([cj]) * ctx([(-(i + 1)) % P, 1]) + ctx([cj1]) * ctx([(-i) % P, 1]))
        i += 2
        if (i & (step - 1)) == 1:
            print(f"      level1 {i}/{n} ({time.time()-t0:.0f}s)", flush=True)
    if i == n:
        Mlev.append(ctx([(-n) % P, 1])); Vlev.append(ctx([take(n)]))
    fh.close()
    print(f"      level1 built: {len(Mlev)} nodes ({time.time()-t0:.0f}s)", flush=True)
    lvl = 1
    while len(Mlev) > 1:                                                 # combine up, free lower level
        Mn = []; Vn = []
        for k in range(0, len(Mlev) - 1, 2):
            Mn.append(Mlev[k] * Mlev[k + 1])
            Vn.append(Vlev[k] * Mlev[k + 1] + Vlev[k + 1] * Mlev[k])
        if len(Mlev) & 1:
            Mn.append(Mlev[-1]); Vn.append(Vlev[-1])
        Mlev = Mn; Vlev = Vn; lvl += 1
        print(f"      combine level {lvl}: {len(Mlev)} nodes ({time.time()-t0:.0f}s)", flush=True)
    return Vlev[0]

def gfp_roots(P, F):
    ctx = _ctx(P)
    x = ctx([0, 1])
    t = time.time()
    try:
        xp = pow(x, int(P), F)
    except Exception:                                                    # manual x^P mod F
        res = ctx([1]); b = x % F; e = int(P)
        while e > 0:
            if e & 1: res = (res * b) % F
            b = (b * b) % F; e >>= 1
        xp = res
    g = F.gcd((xp - x) % F)
    print(f"    phase3: x^P mod F + gcd -> split deg {g.degree()} ({time.time()-t:.1f}s)", flush=True)
    roots = []
    fac = g.factor()
    items = fac[1] if isinstance(fac, tuple) else fac
    for it in items:
        poly = it[0] if isinstance(it, (tuple, list)) else it
        if poly.degree() == 1:
            cf = _coeffs(poly)
            roots.append(int((-mpz(cf[0])) * invert(mpz(cf[1]) % P, P) % P))
    return roots


# --------------------------------------------------------------- build F (eval + interpolate)
def _npts_of(cpos, cneg, d):
    Npos, Nneg = 3**len(cpos), 3**len(cneg)
    Sp = sum(c for c, _ in cpos); Sn = sum(c for c, _ in cneg)
    Dp = 3**(len(cpos) - 1) * Sp if cpos else 0
    Dn = (3**(len(cneg) - 1) * Sn if cneg else 0) + (d if d > 0 else 0) * Nneg
    return Npos, Nneg, int(Npos * Dn + Nneg * Dp) + 2

def build_F(P, cpos, cneg, d, procs, path, fresh=False):
    """Eval F at 1..deg F+1 (checkpointed to `path`) then interpolate. Returns flint poly F."""
    Npos, Nneg, npts = _npts_of(cpos, cneg, d)
    print(f"    deg F <= {npts-2}; |pos|={len(cpos)} |neg|={len(cneg)} d={d}", flush=True)
    if fresh and os.path.exists(path):
        os.remove(path)
    if os.path.exists(path):
        n = os.path.getsize(path) // 18
        print(f"    resuming: {n} evaluations already in {path} (eval skipped)", flush=True)
    else:
        xs, ys = eval_points(P, cpos, cneg, d, Npos, Nneg, npts, procs)
        with open(path, "wb") as f:
            for y in ys:
                f.write(int(y).to_bytes(18, "big"))
        n = len(ys)
        print(f"    checkpointed {n} evaluations -> {path}", flush=True)
        del xs, ys; gc.collect()
    t = time.time()
    F = interpolate_file(P, path, n)
    # NOTE: we do NOT strip x^k factors -- x0 = m^{-C} != 0, so any x=0 root is spurious and is
    # filtered downstream (`if r != 0`). Stripping here is a per-factor O(M(deg)) division on a
    # ~10^8-degree poly (hours) for zero benefit.
    print(f"    interpolated F deg {F.degree()} ({time.time()-t:.0f}s)", flush=True)
    return F

# --------------------------------------------------------------- driver per prime (single relation)
def _recover(P, cpos, cneg, d, chk, procs, m_true=None, ckpt=None):
    F = build_F(P, cpos, cneg, d, procs, ckpt or "values_tmp.bin", fresh=(ckpt is None))
    roots = gfp_roots(P, F)
    inv = int(invert(mpz(C), mpz(P - 1)))
    cands = {int(powmod(mpz(r), (-inv) % (P - 1), mpz(P))) for r in roots if r != 0}
    good = sorted(c for c in cands if _reproduces(P, c, chk))
    msg = f"    {len(cands)} roots -> {len(good)} verified candidate(s)"
    if m_true is not None:
        msg += f"  [true recovered: {m_true % P in good}]"
    print(msg, flush=True)
    return good

# --------------------------------------------------------------- two-relation GCD path
def _files(which, slot):
    if slot == 1:                                                        # slot 1 = your existing run
        return f"relation_{which}.txt", f"values_{which}.bin", f"Fpoly1_{which}.bin"
    return (f"relation{slot}_{which}.txt", f"values{slot}_{which}.bin", f"Fpoly{slot}_{which}.bin")

def save_poly(path, F, P):
    """Write F's coefficients (low->high) as fixed 18-byte big-endian; O(1)-index if available."""
    deg = F.degree()
    try:
        _ = F[0]; idx = True
    except Exception:
        idx = False
    with open(path, "wb") as f:
        if idx:
            buf = bytearray()
            for i in range(deg + 1):
                buf += (int(F[i]) % P).to_bytes(18, "big")
                if len(buf) >= 18 * (1 << 20):
                    f.write(buf); buf = bytearray()
            if buf:
                f.write(buf)
        else:
            for c in F.coeffs():
                f.write((int(c) % P).to_bytes(18, "big"))

def load_poly(path, P):
    ctx = _ctx(P)
    data = open(path, "rb").read()
    n = len(data) // 18
    coeffs = [int.from_bytes(data[i*18:i*18+18], "big") for i in range(n)]
    del data
    return ctx(coeffs)

def build_slot(which, slot, procs):
    """Build F for one relation slot and save it to disk (reuses its values checkpoint)."""
    P = P_REAL if which == "p" else Q_REAL
    rel, val, fp = _files(which, slot)
    P2, cpos, cneg, d, chk = parse_relation(rel)
    assert P2 == P, "relation file prime mismatch"
    t = time.time()
    F = build_F(P, cpos, cneg, d, procs, val)
    print(f"[{which} slot {slot}] F deg {F.degree()} -> {fp} ({time.time()-t:.0f}s)", flush=True)
    save_poly(fp, F, P)

def strip_x(F, P):
    """Return (F / x^v, v) where v = x-valuation. F has a huge x^v factor (x=0 is a spurious
       root of multiplicity ~Npos*Nneg*mono-deg/3); x0 = m^{-C} != 0, so dividing it out is safe
       and turns gcd(F1,F2) from ~x^v*(x-x0) into just the genuine (small) shared part."""
    cs = F.coeffs()
    v = 0
    while v < len(cs) and int(cs[v]) == 0:
        v += 1
    if v == 0:
        return F, 0
    return _ctx(P)([int(c) for c in cs[v:]]), v

def solve_gcd(which):
    """gcd(F1,F2), strip the spurious x^v factor -> tiny poly containing x0 -> root-find -> m mod P."""
    P = P_REAL if which == "p" else Q_REAL
    _, _, fp1 = _files(which, 1); _, _, fp2 = _files(which, 2)
    gpath = f"Gpoly_{which}.bin"
    if os.path.exists(gpath):                                           # resume: gcd already computed
        print(f"loading saved gcd {gpath} ...", flush=True); G = load_poly(gpath, P)
    else:
        print(f"loading {fp1} ...", flush=True); F1 = load_poly(fp1, P); print(f"  F1 deg {F1.degree()}", flush=True)
        print(f"loading {fp2} ...", flush=True); F2 = load_poly(fp2, P); print(f"  F2 deg {F2.degree()}", flush=True)
        t = time.time()
        G = F1.gcd(F2)
        print(f"  gcd deg {G.degree()} ({time.time()-t:.0f}s)", flush=True)
        del F1, F2; gc.collect()
        save_poly(gpath, G, P); print(f"  saved gcd -> {gpath} (insurance)", flush=True)
    G, v = strip_x(G, P)                                                # remove the x^v pollution
    print(f"  stripped x^{v} -> genuine gcd deg {G.degree()}", flush=True)
    if G.degree() > 100000:
        print("  WARNING: genuine gcd still large -> F1/F2 share real roots; use MORE disjoint "
              "samples for relation2 (prep2 <which> <offset>).", flush=True)
    roots = gfp_roots(P, G)                                             # G now tiny -> x^P mod G cheap
    inv = int(invert(mpz(C), mpz(P - 1)))
    cands = {int(powmod(mpz(r), (-inv) % (P - 1), mpz(P))) for r in roots if r != 0}
    _, _, _, _, chk = parse_relation(_files(which, 1)[0])
    good = sorted(c for c in cands if _reproduces(P, c, chk))
    open(f"cands_{which}.txt", "w").write("\n".join(str(c) for c in good))
    print(f"[{which}] gcd path -> {len(good)} candidate(s) -> cands_{which}.txt", flush=True)
    return good

def _reproduces(P, m, chk, checks=8):
    m = m % P
    for a_i, S_i in chk[:checks]:
        b_i = (3 * a_i + C) % (P - 1)
        if (powmod(mpz(m), a_i, mpz(P)) + powmod(mpz(m), b_i, mpz(P))) % P != S_i % P:
            return False
    return True


# --------------------------------------------------------------- relation file I/O
def parse_relation(path):
    P = d = None; cpos = []; cneg = []; chk = []
    for line in open(path):
        t = line.split()
        if not t: continue
        if t[0] == "P": P = int(t[1])
        elif t[0] == "C": pass
        elif t[0] == "d": d = int(t[1])
        elif t[0] == "pos": cpos.append((int(t[1]), int(t[2])))
        elif t[0] == "neg": cneg.append((int(t[1]), int(t[2])))
        elif t[0] == "chk": chk.append((int(t[1]), int(t[2])))
    return P, cpos, cneg, d, chk

def run(which, procs):
    P = P_REAL if which == "p" else Q_REAL
    P2, cpos, cneg, d, chk = parse_relation(f"relation_{which}.txt")
    assert P2 == P, "relation file prime mismatch"
    t = time.time()
    good = _recover(P, cpos, cneg, d, chk, procs, ckpt=f"values_{which}.bin")
    open(f"cands_{which}.txt", "w").write("\n".join(str(c) for c in good))
    print(f"[{which}] {len(good)} candidate(s) -> cands_{which}.txt ({time.time()-t:.1f}s)", flush=True)

def combine():
    def crt(a, b):
        return (a + P_REAL * ((b - a) * pow(P_REAL, -1, Q_REAL) % Q_REAL)) % N_REAL
    cp = [int(x) for x in open("cands_p.txt").read().split()]
    cq = [int(x) for x in open("cands_q.txt").read().split()]
    print(f"combine: {len(cp)} x {len(cq)} CRT pairs", flush=True)
    for mp in cp:
        for mq in cq:
            m = crt(mp, mq) % N_REAL
            b = m.to_bytes((m.bit_length() + 7) // 8, "big")
            if b.startswith(b"HCMUS"):
                print("FLAG:", b.decode("latin1", "replace")); return
    print("no flag among CRT pairs -- gather more candidates (larger n in prep)")


# --------------------------------------------------------------- selftest (self-contained, incl. LLL)
def _lll(B):
    from fractions import Fraction as Fr
    import math
    B = [[Fr(x) for x in row] for row in B]; n = len(B)
    def gs():
        Bs = []; mu = [[Fr(0)] * n for _ in range(n)]
        for i in range(n):
            bi = B[i][:]
            for j in range(i):
                mu[i][j] = sum(B[i][k]*Bs[j][k] for k in range(n)) / sum(Bs[j][k]**2 for k in range(n))
                bi = [bi[k] - mu[i][j]*Bs[j][k] for k in range(n)]
            Bs.append(bi)
        return Bs, mu
    Bs, mu = gs(); k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fr(1, 2):
                r = math.floor(mu[k][j] + Fr(1, 2))
                B[k] = [B[k][t] - r*B[j][t] for t in range(n)]; Bs, mu = gs()
        if sum(Bs[k][t]**2 for t in range(n)) >= (Fr(3, 4) - mu[k][k-1]**2) * sum(Bs[k-1][t]**2 for t in range(n)):
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]; Bs, mu = gs(); k = max(k - 1, 1)
    return [[int(x) for x in row] for row in B]

def _best_relation(P, a):
    n = len(a); W = 1 << (P.bit_length() + 8)
    M = [[0]*(n+2) for _ in range(n+2)]
    for i in range(n):
        M[i][i] = 1; M[i][n+1] = W*a[i]
    M[n][n] = 1; M[n][n+1] = W*C
    M[n+1][n+1] = W*(P-1)
    best = None
    for r in _lll(M):
        if r[n+1] != 0: continue
        rc = r[:n]; d = r[n]
        if not any(rc) and d == 0: continue
        supp = sum(1 for v in rc if v); md = sum(abs(v) for v in rc) + abs(d)
        pred = 3**(supp-1) * (md + 2*abs(d))
        if best is None or pred < best[0]:
            best = (pred, rc, d)
    return best[1], best[2]

def selftest(bits):
    import random
    while True:
        p = gmpy2.next_prime(random.randrange(2**(bits-1), 2**bits))
        if gmpy2.gcd(C, p - 1) == 1:
            break
    p = int(p); q = int(gmpy2.next_prime(random.randrange(2**(bits-1), 2**bits)))
    NN = p * q; m = random.randrange(2, NN)
    n = 6; ks = []
    while len(ks) < n:
        s = random.randrange(731, NN); e1 = (3*s + C) % NN; e2 = (3*e1 + C) % NN
        if (3*e1 + C - e2) // NN == 0:
            ks.append((e1 % (p - 1), (pow(m, e1, p) + pow(m, e2, p)) % p))
    a = [ai for ai, _ in ks]
    rc, d = _best_relation(p, a)
    cpos = [(rc[i], ks[i][1]) for i in range(n) if rc[i] > 0]
    cneg = [(-rc[i], ks[i][1]) for i in range(n) if rc[i] < 0]
    print(f"[selftest bits={bits}] m mod p = {m % p}; support={sum(1 for v in rc if v)} d={d}", flush=True)

    if _have_kernel():                                              # C kernel vs python F_at
        import nier_kernel
        Npos, Nneg = 3**len(cpos), 3**len(cneg)
        K = nier_kernel.NierKernel(str(p), cpos, cneg, d, Npos, Nneg)
        _init(p, cpos, cneg, d, Npos, Nneg)
        ck = K.eval_range(1, 12)
        py = [F_at(v) for v in range(1, 12)]
        ok = ck == py
        print(f"  kernel cross-check (C vs python F_at): {'OK' if ok else 'MISMATCH'}", flush=True)
        if not ok:
            print(f"    C : {ck}\n    py: {py}", flush=True)
    else:
        print("  (nier_kernel not built -- using pure-gmpy2 path; "
              "run: python setup_kernel.py build_ext --inplace)", flush=True)

    good = _recover(p, cpos, cneg, d, ks, procs=1, m_true=m)
    print("  =>", "PASS" if (m % p) in good else "FAIL", flush=True)

def selftest_gcd(bits):
    """Validate the two-relation GCD path end-to-end on a small instance."""
    import random
    while True:
        p = int(gmpy2.next_prime(random.randrange(2**(bits-1), 2**bits)))
        if gmpy2.gcd(C, p - 1) == 1:
            break
    q = int(gmpy2.next_prime(random.randrange(2**(bits-1), 2**bits)))
    NN = p * q; m = random.randrange(2, NN); ks = []
    while len(ks) < 12:
        s = random.randrange(731, NN); e1 = (3*s + C) % NN; e2 = (3*e1 + C) % NN
        if (3*e1 + C - e2) // NN == 0:
            ks.append((e1 % (p - 1), (pow(m, e1, p) + pow(m, e2, p)) % p))
    def mk(idx):
        rc, d = _best_relation(p, [ks[i][0] for i in idx])
        cpos = [(rc[t], ks[idx[t]][1]) for t in range(len(idx)) if rc[t] > 0]
        cneg = [(-rc[t], ks[idx[t]][1]) for t in range(len(idx)) if rc[t] < 0]
        return cpos, cneg, d
    cpos1, cneg1, d1 = mk(list(range(0, 6)))                             # two DIFFERENT relations
    cpos2, cneg2, d2 = mk(list(range(6, 12)))
    print(f"[selftest-gcd bits={bits}] m mod p = {m % p}", flush=True)
    F1 = build_F(p, cpos1, cneg1, d1, 1, "st_v1.bin", fresh=True)
    F2 = build_F(p, cpos2, cneg2, d2, 1, "st_v2.bin", fresh=True)
    G = F1.gcd(F2)
    G, v = strip_x(G, p)                                                 # same x^v strip as solve_gcd
    print(f"  F1 deg {F1.degree()}  F2 deg {F2.degree()}  gcd/x^{v} deg {G.degree()}", flush=True)
    roots = gfp_roots(p, G)
    inv = int(invert(mpz(C), mpz(p - 1)))
    cands = {int(powmod(mpz(r), (-inv) % (p - 1), mpz(p))) for r in roots if r != 0}
    good = sorted(c for c in cands if _reproduces(p, c, ks))
    for f in ("st_v1.bin", "st_v2.bin"):
        if os.path.exists(f):
            os.remove(f)
    print("  =>", "PASS" if (m % p) in good else "FAIL", f"(candidates {good})", flush=True)


if __name__ == "__main__":
    args = sys.argv[1:]
    mode = args[0] if args else "selftest"
    if mode == "selftest":
        selftest(int(args[1]) if len(args) > 1 else 24)
    elif mode == "selftest-gcd":
        selftest_gcd(int(args[1]) if len(args) > 1 else 20)
    elif mode == "run":
        run(args[1], int(args[2]) if len(args) > 2 else os.cpu_count())
    elif mode == "buildF":                                               # buildF <which> <slot> [procs]
        build_slot(args[1], int(args[2]), int(args[3]) if len(args) > 3 else os.cpu_count())
    elif mode == "gcd":                                                  # gcd <which>
        solve_gcd(args[1])
    elif mode == "combine":
        combine()
    else:
        print(__doc__)
