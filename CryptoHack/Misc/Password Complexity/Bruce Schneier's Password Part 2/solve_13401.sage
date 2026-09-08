#!/usr/bin/env sage
r"""
Solve for a password P (subset of \w = [A-Za-z0-9_]) such that

    S = sum(ord(c) for c in P)      is prime
    prod(ord(c) for c in P) == S    as numpy int64

The second condition is the whole challenge: numpy stores the ords in an
int64 array, so `array.prod()` is computed modulo 2**64 (wrapping, signed).
The real requirement is therefore

    prod(ord(c)) === S   (mod 2**64),   with 0 < S < 2**63.

Two consequences:

  1. S is an odd prime  =>  the product is odd  =>  EVERY character is odd.
     That kills the naive "pad with lots of even chars" idea (a v_2 >= 64
     product is 0 mod 2**64, and sum 0 is impossible).

  2. (Z/2**64)* = <-1> x <3>, with ord(3) = 2**62.  Writing each odd char as
     c = (-1)^s_c * 3^l_c, the multiset of characters (multiplicities x_c)
     must satisfy the LINEAR system

        sum_c x_c * c   = S            (over Z)
        sum_c x_c * l_c = l_S mod 2**62
        sum_c x_c * s_c = s_S mod 2

     i.e. a short-vector problem: find x >= 0, entries small, in a coset of a
     rank-31 lattice of determinant ~ 2**63.  Kannan embedding + LLL solves it
     instantly; the deviations from a flat baseline come out around
     (2**63 * det)^(1/31) ~ 5, which matches what we observe.

Usage:  sage solve_13401.sage
"""

import re
from random import shuffle

MOD  = 2 ^ 64
ORD3 = 2 ^ 62          # order of 3 in (Z/2^64)*


# ----------------------------------------------------------------------------
# discrete log in the 2-group (Z/2^64)* -- Hensel lifting, one bit at a time
# ----------------------------------------------------------------------------
def dlog3(y):
    """Return l with 3^l == y (mod 2^64).  Requires y % 8 in {1, 3}."""
    y = Integer(y) % MOD
    assert y % 8 in (1, 3), "y is not in <3>"
    l = Integer(0 if y % 8 == 1 else 1)          # 3^l == y (mod 8)
    for k in range(3, 64):
        m = 2 ^ (k + 1)
        if (power_mod(3, l, m) - y) % m != 0:
            # 3^(2^(k-2)) == 1 + 2^k (mod 2^(k+1)) is exactly the correction
            l += 2 ^ (k - 2)
    return l % ORD3


def decomp(y):
    """y odd -> (s, l) with y == (-1)^s * 3^l (mod 2^64)."""
    s = 0 if y % 8 in (1, 3) else 1
    return s, dlog3((-1) ^ s * Integer(y) % MOD)


# ----------------------------------------------------------------------------
# character set: \w characters with ODD ord  (see note 1 above)
# ----------------------------------------------------------------------------
WORD_CHARS = ([c for c in range(0x30, 0x3A)] +      # 0-9
              [c for c in range(0x41, 0x5B)] +      # A-Z
              [c for c in range(0x61, 0x7B)] +      # a-z
              [0x5F])                               # _
CH = [c for c in WORD_CHARS if c % 2 == 1]
N  = len(CH)                                        # 32
DEC = [decomp(c) for c in CH]
SGN = [d[0] for d in DEC]
LOG = [d[1] for d in DEC]
TOT = sum(CH)

for c, s, l in zip(CH, SGN, LOG):
    assert ((-1) ^ s * power_mod(3, l, MOD)) % MOD == c


# ----------------------------------------------------------------------------
# lattice step: find multiplicities x >= 0 with sum(x_c*c) = S and
#               prod(c^x_c) == S (mod 2^64), x_c close to the baseline m
# ----------------------------------------------------------------------------
def solve_multiplicities(m, S, W=2 ^ 40):
    """Kannan embedding: columns are [ x | W*sum | W*dlog | W*sign | pivot ]."""
    sS, lS = decomp(S)

    rows = []
    for i in range(N):                       # one row per character
        r = [0] * (N + 4)
        r[i]     = 1
        r[N + 0] = W * CH[i]
        r[N + 1] = W * LOG[i]
        r[N + 2] = W * SGN[i]
        rows.append(r)
    rows.append([0] * N + [0, W * ORD3, 0, 0])   # dlog is only defined mod 2^62
    rows.append([0] * N + [0, 0, W * 2, 0])      # sign is only defined mod 2
    rows.append([-m] * N + [-W * S, -W * lS, -W * sS, 1])   # target / pivot

    B = Matrix(ZZ, rows).LLL()

    for row in B:
        for sign in (1, -1):
            v = [sign * t for t in row]
            if v[-1] != 1:                       # target used exactly once
                continue
            if any(v[N + k] != 0 for k in range(3)):
                continue                         # constraints not satisfied
            x = [v[i] + m for i in range(N)]
            if min(x) < 0:                       # multiplicities must be >= 0
                continue
            return x
    return None


def build_password(x, randomize=True):
    chars = []
    for c, k in zip(CH, x):
        chars += [chr(c)] * int(k)
    if randomize:
        shuffle(chars)                           # order is irrelevant, cosmetic
    return "".join(chars)


# ----------------------------------------------------------------------------
# replica of the server-side check(), including the int64 wraparound
# ----------------------------------------------------------------------------
def check(password):
    if not re.fullmatch(r"\w*", password, flags=re.ASCII):
        return "Password contains invalid characters."
    if not re.search(r"\d", password):
        return "Password should have at least one digit."
    if not re.search(r"[A-Z]", password):
        return "Password should have at least one upper case letter."
    if not re.search(r"[a-z]", password):
        return "Password should have at least one lower case letter."

    ords = [ord(ch) for ch in password]
    s = sum(ords)
    p = prod(ords) % MOD                         # exactly what int64 does
    if p >= 2 ^ 63:
        p -= MOD                                 # signed reinterpretation
    if is_prime(s) and s == p:
        return "PASS"
    return "Wrong password, sum was %d and product was %d" % (s, p)


# ----------------------------------------------------------------------------
def search(m=1, max_primes=64):
    """Baseline multiplicity m: password length ~ 32*m + O(1)."""
    S = Integer(m * TOT)
    for _ in range(max_primes):
        S = next_prime(S)
        x = solve_multiplicities(m, S)
        if x is None:
            continue
        pw = build_password(x)
        if check(pw) == "PASS":
            return pw, S
    return None, None


if __name__ == "__main__":
    for m in (1, 2, 3, 4, 6):
        pw, S = search(m)
        if pw:
            print("[+] m = %d, length = %d, S = %s" % (m, len(pw), S))
            print("[+] password: %s" % pw)
            print("[+] check():  %s" % check(pw))
            break
    else:
        raise SystemExit("[-] no solution found, widen the prime search")

    # optional: numpy cross-check against the literal challenge code
    try:
        import numpy as np, warnings
        warnings.simplefilter("ignore")
        a = np.array(list(map(ord, pw)))
        print("[+] numpy: sum = %d, prod = %d, equal = %s"
              % (a.sum(), a.prod(), a.sum() == a.prod()))
    except ImportError:
        pass

    # optional: fire it at the CryptoHack listener
    #   import json, socket, telnetlib
    #   s = socket.create_connection(("socket.cryptohack.org", 13401))
    #   f = s.makefile("rw")
    #   print(f.readline())                      # Schneier fact
    #   f.write(json.dumps({"password": pw}) + "\n"); f.flush()
    #   print(f.readline())
