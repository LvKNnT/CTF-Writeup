# Number Castle Writeup

## Summary

The service asks for the plaintext message for five RSA stages. Each stage uses a different intentionally weak RSA setup. After solving all five stages, the service prints the flag.

Flag:

```text
HCMUS-CTF{RSA_is_so00000OOOOOOOOOOO_easyyyyyyy_r1ght?}
```

## Triage

No source code was provided, so I first connected to the service and captured the prompts. Every stage printed RSA parameters in the form:

```text
If N = ...; e = ... and c = ..., so what is the message?
```

The answers were not decimal integers. The decrypted integers decoded to printable ASCII hex-like strings, and those byte strings had to be sent back.

## Solve Path

### Stage 1: small exponent without padding

Stage 1 used `e = 3`, and the ciphertext was much smaller than `N`. This suggested there was no modular wraparound:

```text
c = m^3
```

So the message is just the exact integer cube root of `c`:

```python
root, exact = iroot_exact(c, 3)
assert exact
answer = long_to_bytes(root)
```

### Stage 2: Wiener's attack

Stage 2 gave a 1024-bit RSA modulus and a very large public exponent. The quick checks ruled out shared factors and close primes, but the large `e` suggested a small private exponent `d`.

For RSA:

```text
e*d - k*phi(N) = 1
```

If `d` is small enough, `k/d` appears among the continued fraction convergents of `e/N`. For each convergent `(k, d)`, compute:

```text
phi = (e*d - 1) / k
s = N - phi + 1 = p + q
disc = s^2 - 4N
```

When `disc` is a square, `p` and `q` are recovered. In this challenge the recovered `d` directly decrypted the ciphertext:

```python
d = wiener(N, e)
m = pow(c, d, N)
answer = long_to_bytes(m)
```

### Stage 3: close primes and non-invertible exponent

Stage 3 used a fixed `N` and `e = 69`. Fermat factorization worked immediately because the primes were very close:

```text
N = p*q, where p ~= q
```

After factoring, `e` was not invertible modulo `phi(N)` because:

```text
gcd(69, phi(N)) = 3
```

So normal RSA decryption was not possible. Instead, solve roots modulo each prime.

For each prime:

```text
g = gcd(e, prime - 1)
```

If `g = 1`, invert `e` normally. If `g > 1`, remove the invertible part first, then take the `g`-th modular roots:

```python
reduced_e = e // g
reduced = pow(c, inverse(reduced_e, prime - 1), prime)
roots = nthroot_mod(reduced, g, prime, True)
```

Then combine roots with CRT and select the only printable candidate.

### Stage 4: small factor

Stage 4 used standard `e = 65537`, but the modulus was only about 527 bits. Trial factoring immediately found a small factor:

```text
31337 | N
```

With `p = 31337` and `q = N / p`, compute `phi(N)`, invert `e`, and decrypt:

```python
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, N)
```

### Stage 5: leaked expression involving d and p

Stage 5 gave a standard-looking 1024-bit `N` with `e = 65537`, plus one extra huge value in the prompt (bigger than `N`, so it couldn't be `c`). Before trusting that value as useful, I first checked whether stage 5 was breakable by factoring `N` alone:

- `gcd(c, N)`, `gcd(c±1, N)`, trial division, Mersenne/Fermat/Pollard p-1/Williams p+1, a ROCA fingerprint check, gmp-ecm with a 600s budget, a Hilbert-class-polynomial (CM) special-form curve search, and a full RsaCtfTool pass over its non-hopeless attack list (`hart`, `lehman`, `kraitchik`, `small-fraction`, `lattice`, `boneh_durfee`, `small_crt_exp`, etc.)

All of these failed - `N` is a genuine balanced semiprime with no exploitable structure. That ruled out pure factoring and confirmed the extra huge value in the prompt had to be the actual attack surface: it was a leak of

```text
g = d * (p - 0xabadc0de)
```

Let:

```text
a = 0xabadc0de
g = d * (p - a)
```

RSA also gives:

```text
e*d - 1 = k*phi(N)
```

Since `e = 65537`, the unknown multiplier `k` is small:

```text
1 <= k <= e
```

Substitute `d = g / (p - a)`. Since `phi(N)` is close to `N`, this gives a good estimate:

```text
p ~= floor(e*g / (k*N)) + a
```

Looping over all `k` from `1` to `65537` and checking a small window around the estimate recovers an exact divisor of `N`:

```python
for k in range(1, e + 1):
    p0 = (e * g) // (k * N) + 0xABADC0DE
    for p in range(p0 - 100, p0 + 101):
        if N % p == 0:
            q = N // p
            decrypt_with_factors(N, e, c, {p: 1, q: 1})
```

This is a bounded algebraic search over at most `65537 * 201` candidates, with exact divisibility as the oracle.

## Exploit

The final solver is [solve.sage](#Solve) (a Sage script - Sage's `Integer`/`nth_root`/`GF` arithmetic is used for the modular n-th roots in stage 3). It connects to the remote, parses each prompt for `N`, `e`, `c`, and (on the last floor) the extra leaked value, applies the stage-specific RSA break, sends the decoded byte message, and continues until the flag is printed.

Run:

```bash
sage solve.sage
```

Relevant helpers:

- `iroot_exact`: exact e-th root for Stage 1 (`e` small, `c` unwrapped)
- `wiener`: continued-fraction attack for Stage 2 (small private exponent)
- `fermat` / `small_factor`: close-prime and small-factor recovery for Stages 3 and 4
- `decrypt_with_factors` + `semiprime_roots`: CRT combination and per-prime `e`-th roots when `gcd(e, phi(N)) > 1` (Stage 3)
- `leaked_g_attack`: bounded `k` search recovering `p` from the leaked `d * (p - 0xabadc0de)` (Stage 5)

## Solve

```python=

import re
from pwn import *
from Crypto.Util.number import long_to_bytes

context.log_level = "debug"

HOST = ???
PORT = ???

A_CONST = 0xABADC0DE


# --------------------------------------------------------------- primitives

def iroot_exact(c, e):
    r, exact = Integer(c).nth_root(int(e), truncate_mode=True)
    return int(r), bool(exact)


def wiener(e, n):
    num, den = int(e), int(n)
    cf = []
    while den:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    h0, h1, k0, k1 = 0, 1, 1, 0
    for a in cf:
        h0, h1 = h1, a * h1 + h0
        k0, k1 = k1, a * k1 + k0
        k, d = h1, k1
        if k == 0 or d == 0 or (int(e) * d - 1) % k != 0:
            continue
        phi = (int(e) * d - 1) // k
        s = int(n) - phi + 1
        disc = s * s - 4 * int(n)
        if disc < 0:
            continue
        t = isqrt(disc)
        if t * t == disc:
            return int(d)
    return None


def fermat(n, max_iter=2_000_000):
    n = int(n)
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return [int(a - b), int(a + b)]
        a += 1
    return None


def small_factor(n, bound=10_000_000):
    n = int(n)
    for p in primes(bound):
        if n % int(p) == 0:
            return [int(p), n // int(p)]
    return None


# ------------------------------------------------- decrypt given the factors

def is_printable(b):
    return len(b) > 0 and all(0x20 <= x < 0x7f for x in b)


def pick_printable(cands):
    printable = [(m, long_to_bytes(int(m))) for m in cands
                 if is_printable(long_to_bytes(int(m)))]
    for m, b in printable:                          
        if all(ch in b"0123456789abcdef" for ch in b):
            return int(m)
    if printable:
        return int(printable[0][0])
    return int(cands[0]) if cands else None


def semiprime_roots(n, e, c, p, q):
    def roots(pp):
        Fp = GF(pp)
        v = Fp(int(c) % int(pp))
        if v == 0:
            return [0]
        try:
            return [int(r) for r in v.nth_root(int(e), all=True)]
        except (ValueError, ArithmeticError):
            return []
    inv = inverse_mod(int(p), int(q))
    out = []
    for rp in roots(p):
        for rq in roots(q):
            m = int((rp + p * ((rq - rp) * inv % q)) % n)
            if pow(m, int(e), int(n)) == int(c) % int(n):
                out.append(m)
    return out


def decrypt_with_factors(n, e, c, p, q):
    n, e, c, p, q = int(n), int(e), int(c), int(p), int(q)
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) == 1:
        return int(pow(c, int(inverse_mod(e, phi)), n))
    return pick_printable(semiprime_roots(n, e, c, p, q))   


# ------------------------------------------------------- stage 5 leak attack

def leaked_g_attack(n, e, c, g):
    n, e, g = int(n), int(e), int(g)
    for k in range(1, e + 1):
        p0 = (e * g) // (k * n) + A_CONST
        for p in range(p0 - 100, p0 + 101):
            if p > 1 and n % p == 0:
                return decrypt_with_factors(n, e, c, p, n // p)
    return None


# ------------------------------------------------------------- dispatcher

def solve_stage(n, e, c, leak):
    n, e, c = int(n), int(e), int(c)

    if leak is not None:                       # stage 5: leaked d*(p-a)
        return leaked_g_attack(n, e, c, leak)

    if e.bit_length() <= 40:                   # stage 1: small e, exact root
        r, exact = iroot_exact(c, e)
        if exact:
            return int(r)

    d = wiener(e, n)                           # stage 2: tiny d
    if d is not None:
        return int(pow(c, d, n))

    pq = fermat(n) or small_factor(n)          # stages 3 & 4: factorable N
    if pq is not None:
        return decrypt_with_factors(n, e, c, pq[0], pq[1])

    return None


def main():
    io = remote(HOST, PORT)

    while True:
        try:
            chunk = io.recvuntil(b">>> ", timeout=30)
        except EOFError:
            break
        text = chunk.decode(errors="replace")

        pairs = dict(re.findall(r"\b([A-Za-z_]\w*)\s*=\s*(\d+)", text))
        if not {"N", "e", "c"} <= set(pairs):
            print(text)                        
            break

        n = int(pairs["N"])
        e = int(pairs["e"])
        c = int(pairs["c"])
        big = max(int(x) for x in re.findall(r"\d+", text))
        leak = big if big > n else None

        tag = "leak" if leak is not None else f"e={e.bit_length()}b"
        print(f"[stage] N={n.bit_length()}b {tag}")

        m = solve_stage(n, e, c, leak)
        if m is None:
            print("!! failed to solve this stage")
            print(text)
            break

        io.sendline(long_to_bytes(m))

        if leak is not None:                   # stage 5 is the last floor
            print(io.recvall(timeout=5).decode(errors="replace"))
            break


if __name__ == "__main__":
    main()
```

## Verification

The solver was run against the live service and completed all five stages. The final output was:

```text
Well done, here is your reward!
HCMUS-CTF{RSA_is_so00000OOOOOOOOOOO_easyyyyyyy_r1ght?}
```

## Flag

```text
HCMUS-CTF{RSA_is_so00000OOOOOOOOOOO_easyyyyyyy_r1ght?}
```

## Lessons Learned

- Low public exponent without padding allows integer root recovery when the ciphertext never wraps modulo `N`.
- A small private exponent enables Wiener's continued-fraction attack, regardless of how large `e` looks.
- Close primes make Fermat factorization immediate - always try it before reaching for heavier tools.
- A non-coprime `e` (i.e. `gcd(e, phi(N)) > 1`) breaks normal modular inversion; recover the message via per-prime `e`-th roots and CRT instead, disambiguating candidates by printability.
- Before trusting an "obviously extra" value in a prompt as the intended attack, first rule out plain factoring (small factors, Fermat, Pollard p-1/p+1, ECM, special-form primes) - a clean negative result is itself the signal that points at the real vulnerability.
- A leaked algebraic expression mixing `d` and `p` can still be inverted: combine it with `e*d - 1 = k*phi(N)` (small `k` for small `e`) and `phi(N) ~= N` to get a close numerical estimate of `p`, then confirm with exact divisibility over a small search window.
