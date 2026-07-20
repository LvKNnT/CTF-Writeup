# Count degree-48 divisors of x^N - 1 over GF(2), N = 23738715.
# Irreducible factors of x^N-1 have degree = ord_d(2) for each divisor d|N,
# with multiplicity phi(d)/ord_d(2).  No need to factor the huge polynomial.

from sympy import divisors, totient, n_order

N = 23738715  # = 3^2 * 5 * 7 * 11 * 13 * 17 * 31  (odd -> x^N-1 squarefree over GF(2))

divs = divisors(N)
# degree multiset: for each d, phi(d)/ord_d(2) factors of degree ord_d(2)
deg_mult = {}   # degree -> count of irreducible factors of that degree
total_factors = 0
total_deg = 0
for d in divs:
    if d == 1:
        deg = 1; cnt = 1  # factor (x-1)
    else:
        deg = n_order(2, d)        # multiplicative order of 2 mod d
        cnt = totient(d) // deg
    deg_mult[deg] = deg_mult.get(deg, 0) + cnt
    total_factors += cnt
    total_deg += deg * cnt

print("N =", N)
print("num divisors of N:", len(divs))
print("total irreducible factors of x^N-1:", total_factors)
print("sum of degrees (should == N):", total_deg)
print("degree distribution (deg: #factors):")
for deg in sorted(deg_mult):
    print(f"   deg {deg}: {deg_mult[deg]} factors")

# DP: number of degree-48 sub-multiset selections (each factor used 0/1 times).
# coefficient of x^48 in prod over factors (1 + x^deg).  Track up to degree 48.
TARGET = 48
dp = [0]*(TARGET+1)
dp[0] = 1
for deg, cnt in deg_mult.items():
    if deg > TARGET:
        continue
    for _ in range(cnt):
        for s in range(TARGET, deg-1, -1):
            dp[s] += dp[s-deg]
        # cap to avoid overflow blowup is unnecessary in python

num48 = dp[TARGET]
print()
print("number of degree-48 divisors of x^N-1 (=feedback polys with order | N):", num48)
import math
print("log2:", math.log2(num48) if num48>0 else None)
print("fraction of all 2^48 degree-48 polys:", num48 / 2**48)
print("expected hits among 2002 random windows:", num48 / 2**47 * 2002)
