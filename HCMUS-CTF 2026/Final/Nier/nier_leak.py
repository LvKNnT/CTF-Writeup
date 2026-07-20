#!/usr/bin/env python3
# =====================================================================================
# NieR --- pure-Python helper (no SageMath).
# Covers the parts that don't need a computer-algebra system:
#   - parse output.txt
#   - replay the LCG on each leaked [DEBUG] seed -> recover both exponents of every sum
#   - verify a candidate flag against all 136 published sums
#   - CRT-combine candidate files (cands_p.txt, cands_q.txt) and decode the flag
#
# The heavy recovery of m (LLL + cubic elimination) lives in nier_solve.sage.
#
# USAGE
#   python nier_leak.py verify                 # confirm the known flag
#   python nier_leak.py exponents [k]          # dump first k recovered (e1,e2) exponents
#   python nier_leak.py combine                # CRT cands_p.txt x cands_q.txt -> flag
# =====================================================================================
import re, sys

C = 1337
FLAG_BYTES = b"HCMUS-CTF{E_L4_0_tHe:tH4NKs_Elita}"

# factored N (see factors.txt / WRITEUP.md sec.3)
P = 127673904854512340377644327691421646283087
Q = 160733401619738555510927171021360193926549


def lcg(s, n): return (3 * s + C) % n


def load():
    nums = [int(t) for t in re.findall(r'\d+', open("output.txt").read())]
    N = nums[0]
    body = nums[1:]
    sums, seeds = body[0::2], body[1::2]
    assert P * Q == N, "cached p,q do not multiply to N"
    # usable samples: leaked seed s_i pairs with the NEXT sum (sum_0 uses the unseen e0)
    pairs = [(seeds[i], sums[i + 1]) for i in range(len(seeds) - 1)]
    return N, pairs


def verify():
    N, pairs = load()
    m = int.from_bytes(FLAG_BYTES, "big")
    print(f"flag = {FLAG_BYTES.decode()!r}")
    print(f"m has {m.bit_length()} bits ; N has {N.bit_length()} bits ; m < N : {m < N}")
    ok = 0
    for seed, S in pairs:
        e1 = lcg(seed, N); e2 = lcg(e1, N)
        if pow(m, e1, N) + pow(m, e2, N) == S:      # integer add, NOT reduced mod N
            ok += 1
    print(f"matched {ok}/{len(pairs)}  ->  flag {'CONFIRMED' if ok == len(pairs) else 'WRONG'}")


def exponents(k):
    N, pairs = load()
    print(f"{len(pairs)} usable samples; showing first {k}:")
    for seed, S in pairs[:k]:
        e1 = lcg(seed, N); e2 = lcg(e1, N)
        wrap = (3 * e1 + C - e2) // N
        print(f"  e1={e1}\n  e2={e2}  k(wrap)={wrap}\n  sum={S}\n")


def _crt(a, p, b, q):
    # x = a (mod p), x = b (mod q)
    return (a + p * ((b - a) * pow(p, -1, q) % q)) % (p * q)


def combine():
    N = P * Q
    cp = [int(t) for t in open("cands_p.txt").read().split()]
    cq = [int(t) for t in open("cands_q.txt").read().split()]
    print(f"combine: {len(cp)} x {len(cq)} = {len(cp) * len(cq)} CRT pairs")
    for mp in cp:
        for mq in cq:
            m = _crt(mp, P, mq, Q) % N
            b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
            if b.startswith(b"HCMUS"):
                print("FLAG:", b.decode('latin1', 'replace'))
                return
    print("no flag among CRT combinations -- gather more candidates (larger n)")


if __name__ == '__main__':
    args = sys.argv[1:]
    if not args or args[0] == 'verify':
        verify()
    elif args[0] == 'exponents':
        exponents(int(args[1]) if len(args) > 1 else 3)
    elif args[0] == 'combine':
        combine()
    else:
        print(__doc__)
