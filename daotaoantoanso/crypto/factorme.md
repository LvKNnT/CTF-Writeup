# FactorMe Writeup

## Summary

This is a remote-only crypto challenge.

Each of 30 rounds hands the client both the RSA-like modulus `N` (a product of 5-20 distinct primes of 96-256 bits each) and its totient `phi(N)` directly, then asks only for the *count* of distinct prime factors - all under a single 60-second server-side timer covering every round. The core vulnerability is that knowing `phi(N)` is enough to factor `N` completely (the same trick used to factor RSA moduli given `d` and `e`), so the count can be computed exactly and fast enough to clear all 30 rounds inside the alarm.

Flag:

```text
HCMUS-CTF{H0p3_y0u_didn7_f4ct0r1s3_th353_Ns_a4bfdfca08e0a7329d6cb35bfed23341}
```

## Triage

`chal.py` builds each round's modulus from a random number of random-sized distinct primes, and volunteers the totient right alongside it:

```python
def generateN(self, n_bits, n_primes):
    primes = set()
    while len(primes) < n_primes:
        p = getPrime(n_bits)
        primes.add(p)
    return list(primes), prod(primes)

def getParam(self):
    n_bits = randint(96, 256)
    n_primes = randint(5, 20)
    return n_bits, n_primes
```

```python
primes, N = self.generateN(n_bits, n_primes)
phi = prod([p - 1 for p in primes])

print(f'This is public key: {N}')
print(f'Here is a little hint phi(N): {phi}')
```

The client only has to answer with `len(primes)` - the exact count of distinct prime factors of `N` - for that round to pass; a wrong count ends the connection immediately (`exit(0)`), and the flag is only printed after round 30 succeeds:

```python
primes_cnt = int(input('How many primes factors does N have'))
if primes_cnt == len(primes):
    if i == ROUNDS - 1:
        print("Great job. Here is your flag:", FLAG)
    else:
        print("Very good. How about this one.")
else:
    print("Wrong numbers of prime factors. Lucky next time")
    exit(0)
```

The whole 30-round loop runs under one `signal.alarm(60)`, and the server's own comment notes generation alone eats ~20-22s of that budget - so the client-side factoring/counting logic has to be cheap and fast, not just correct.

Never having to reconstruct the individual primes - only their count - plus being handed `phi(N)` directly, is the giveaway: this is structurally identical to "factor `N` given `d` and `e`" in RSA, generalized to more than two prime factors.

## Solve Path

For any modulus `m` and any exponent `phi` that is a multiple of the multiplicative order of elements mod each of `m`'s prime factors (which `phi(N)` always is, since `(p_i - 1) | phi(N)` for every factor `p_i`), write `phi = 2^s * t` with `t` odd. For a random base `a` coprime to `m`, repeatedly squaring `a^t mod m` up to `s` times must reach `1`; the value immediately before the *first* `1` reached is, with good probability, a nontrivial square root of unity mod `m` (`x^2 == 1` but `x != +-1`). Because `x == +-1` independently modulo each prime factor of `m`, `gcd(x - 1, m)` splits `m` into two nontrivial coprime pieces:

```python
def try_split(m, s, t):
    a = random.randrange(2, m - 1)
    g = math.gcd(a, m)
    if g != 1:
        return g
    x = pow(a, t, m)
    if x == 1 or x == m - 1:
        return None
    for _ in range(s - 1):
        y = pow(x, 2, m)
        if y == 1:
            return math.gcd(x - 1, m)
        if y == m - 1:
            return None
        x = y
    return None
```

`try_split` is retried until it produces a genuine nontrivial factor:

```python
def split(m, s, t):
    while True:
        r = try_split(m, s, t)
        if r is not None and r != 1 and r != m:
            return r
```

The key extra observation (called out directly in the solve script's comments) is that `phi(N)` stays valid for splitting *any* coprime divisor of `N` further, since for a divisor built from a subset of the original primes, `phi(divisor)` always divides `phi(N)`. So the same `s, t` derived once from `phi(N)` can be reused to recursively split every sub-factor down to primes, with no need to ever recover the individual `p_i` values or compute a fresh totient per split:

```python
def factor_count(n, phi):
    t = phi
    s = 0
    while t % 2 == 0:
        t //= 2
        s += 1

    count = 0
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if Integer(m).is_pseudoprime():
            count += 1
            continue
        f = split(m, s, t)
        stack.append(f)
        stack.append(m // f)
    return count
```

Each stack entry is tested for primality with a fast probabilistic check (`is_pseudoprime`); composite entries get split again with the same `(s, t)`. The final `count` is exactly the number of distinct prime factors the server wants - computed without ever knowing the primes themselves.

## Exploit

[solve.sage](#Solve) connects to the remote service, and for each of the 30 rounds parses `N` and `phi(N)` out of the banner text, runs `factor_count` to recover the number of distinct prime factors, and sends that count back before moving to the next round; after round 30 it drains and prints whatever the server sends (the flag banner).

Run:

```bash
sage solve.sage
```

Key steps:

- `try_split(m, s, t)`: one attempt at finding a nontrivial square root of unity mod `m` via a random base, returning a candidate `gcd`-derived factor.
- `split(m, s, t)`: retries `try_split` until a genuine nontrivial factor of `m` is found.
- `factor_count(n, phi)`: derives `s, t` from `phi` once, then recursively splits `n` on a stack until every remaining chunk passes `is_pseudoprime()`, returning the leaf count.
- `main()`: drives the network protocol - parses `N`/`phi(N)` each round, sends `factor_count(n, phi)` back, and repeats for all 30 rounds before printing the server's final response.

## Solve

```python
import math
import random
from pwn import *

context.log_level = "error"

HOST = "vm.daotao.antoanso.org"
PORT = 32787  # <-- set the FactorMe port

ROUNDS = 30


def try_split(m, s, t):
    a = random.randrange(2, m - 1)
    g = math.gcd(a, m)
    if g != 1:
        return g
    x = pow(a, t, m)
    if x == 1 or x == m - 1:
        return None
    for _ in range(s - 1):
        y = pow(x, 2, m)
        if y == 1:
            return math.gcd(x - 1, m)
        if y == m - 1:
            return None
        x = y
    return None


def split(m, s, t):
    while True:
        r = try_split(m, s, t)
        if r is not None and r != 1 and r != m:
            return r


def factor_count(n, phi):
    t = phi
    s = 0
    while t % 2 == 0:
        t //= 2
        s += 1

    count = 0
    stack = [n]
    while stack:
        m = stack.pop()
        if m == 1:
            continue
        if Integer(m).is_pseudoprime():
            count += 1
            continue
        f = split(m, s, t)
        stack.append(f)
        stack.append(m // f)
    return count


def main():
    io = remote(HOST, PORT)

    for i in range(ROUNDS):
        io.recvuntil(b"This is public key: ")
        n = int(io.recvline().strip())
        io.recvuntil(b"phi(N): ")
        phi = int(io.recvline().strip())

        cnt = factor_count(n, phi)
        io.sendline(str(cnt).encode())
        print(f"round {i}: n_bits~{n.bit_length()} -> {cnt} factors")

    print(io.recvall(timeout=5).decode(errors="replace"))


if __name__ == "__main__":
    main()
```

## Verification

```text
round 0: n_bits~3210 -> 20 factors
round 1: n_bits~2205 -> 14 factors
round 2: n_bits~4330 -> 18 factors
round 3: n_bits~2456 -> 17 factors
round 4: n_bits~1462 -> 6 factors
round 5: n_bits~2680 -> 15 factors
round 6: n_bits~2047 -> 10 factors
round 7: n_bits~1142 -> 8 factors
round 8: n_bits~2556 -> 10 factors
round 9: n_bits~1745 -> 14 factors
round 10: n_bits~1732 -> 7 factors
round 11: n_bits~2711 -> 17 factors
round 12: n_bits~3308 -> 17 factors
round 13: n_bits~3354 -> 16 factors
round 14: n_bits~1277 -> 8 factors
round 15: n_bits~801 -> 6 factors
round 16: n_bits~972 -> 8 factors
round 17: n_bits~730 -> 6 factors
round 18: n_bits~1110 -> 8 factors
round 19: n_bits~2032 -> 17 factors
round 20: n_bits~3488 -> 18 factors
round 21: n_bits~1943 -> 13 factors
round 22: n_bits~569 -> 5 factors
round 23: n_bits~857 -> 6 factors
round 24: n_bits~4004 -> 18 factors
round 25: n_bits~1788 -> 9 factors
round 26: n_bits~1829 -> 14 factors
round 27: n_bits~1569 -> 15 factors
round 28: n_bits~1629 -> 7 factors
round 29: n_bits~1847 -> 10 factors
How many primes factors does N have: Great job. Here is your flag: HCMUS-CTF{H0p3_y0u_didn7_f4ct0r1s3_th353_Ns_a4bfdfca08e0a7329d6cb35bfed23341}
```

## Flag

```text
HCMUS-CTF{H0p3_y0u_didn7_f4ct0r1s3_th353_Ns_a4bfdfca08e0a7329d6cb35bfed23341}
```

## Lessons Learned

- Knowing `phi(N)` (or, equivalently, the RSA private exponent `d` alongside `e`) is enough to factor `N` completely via the nontrivial-square-root-of-unity `gcd` trick - the same technique factors two-prime RSA moduli and multi-prime moduli alike.
- The trick generalizes recursively: any exponent that is a multiple of the order of elements modulo every prime factor of a composite (not just `N` itself, but any of its divisors) can be reused to keep splitting sub-factors, without ever deriving a fresh totient per split.
- A probabilistic primality test is enough to terminate the recursion - there is no need to fully certify primality to get a correct factor count.
- When a challenge volunteers what looks like a "hint" alongside a modulus, check first whether that hint alone trivially breaks the modulus's hardness assumption before looking for a harder attack.
- Time-boxed multi-round oracles reward optimizing the core primitive (here, fast probabilistic factor-splitting) over correctness-only approaches that would be too slow to finish inside the shared timer.
