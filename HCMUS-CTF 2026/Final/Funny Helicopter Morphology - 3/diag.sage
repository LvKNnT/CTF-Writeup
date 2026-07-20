#!/usr/bin/env sage
import json
d  = json.load(open("data.json"))
s1 = json.load(open("stage1_out.json"))
q  = Integer(d["q"])
S     = [Integer(x) for x in s1["S"]]
OTP   = [Integer(x) for x in d["otp"]]
s_aux = [Integer(x) for x in s1["s_aux"]]

print("q nbits:", q.nbits())
print("S   nbits:", [x.nbits() for x in S])
print("OTP nbits:", [x.nbits() for x in OTP])
print("\ns_aux values (index : nbits : value : (q-v).nbits):")
for i, v in enumerate(s_aux):
    print(f"  {i:2d}  {v.nbits():3d}  {int(v)}   q-v:{(q-v).nbits()}")

# ---- replicate OpenFHE descending NTT-prime selection ----
def largest_primes(count, bits, M):
    """largest `count` primes < 2^bits with p % M == 1, descending."""
    p = Integer(1) << bits
    cand = p - (p % M) + 1
    if cand >= p:
        cand -= M
    res = []
    while len(res) < count:
        if Integer(cand).is_prime():
            res.append(Integer(cand))
        cand -= M
    return res

print("\n==== prime replication check (main, M=64) ====")
for cnt in (4,):
    mp = largest_primes(cnt, 60, 64)
    print(f"  count={cnt} product==q ? {prod(mp)==q}")
    print("  primes(desc):", mp)

print("\n==== q_aux candidates (aux ring, n=8 -> M=16) ====")
def center_mod(v, m):
    v %= m
    return v - m if v > m // 2 else v

for cnt in (3, 4, 5):
    ap = largest_primes(cnt, 60, 16)
    qaux = prod(ap)
    otp_msb = qaux.nbits()
    print(f"\n  -- {cnt} primes: q_aux nbits={qaux.nbits()}  otpBound=2^{otp_msb-2}")
    print(f"     q_aux>q:{qaux>q}  q_aux<2q:{qaux<2*q}  q_aux<3q:{qaux<3*q}")
    # for each recovered value, see if some lift v+k*q (0<=v+kq<q_aux) centers small
    good = 0
    sizes = []
    for v in s_aux:
        best = None
        k = 0
        while v + k*q < qaux:
            c = center_mod(v + k*q, qaux)
            if best is None or abs(c) < abs(best):
                best = c
            k += 1
        if best is not None:
            sizes.append(Integer(abs(best)).nbits())
            if abs(best) < (Integer(1) << 200):
                good += 1
    print(f"     #values that center to <2^200: {good}/32 ; centered nbits min/max: "
          f"{min(sizes) if sizes else '-'}/{max(sizes) if sizes else '-'}")
