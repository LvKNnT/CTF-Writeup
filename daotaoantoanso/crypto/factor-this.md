# Factor this Writeup

## Summary

The vulnerability is a deliberately weak 512-bit RSA prime `p` constructed as a sum of two squares via a smooth-number Brahmagupta-Fibonacci composition, which makes `p + 1` (on the correct quartic twist) smooth - enabling a CM elliptic-curve (`j = 1728`) ECM-style factorization of `n` without ever brute-forcing or trial-dividing it directly.

Flag:

```text
HCMUS-CTF{Woa!!_you_know_a_lot_about_Elliptic_Curve}
```

## Triage

`factor_this.py` builds one RSA prime through a custom `gen_weird_prime` routine instead of `getPrime`:

```python
def two_square_multiply(a, b):
    u = a[0]*b[0] + a[1]*b[1]
    v = abs(a[0]*b[1] - a[1]*b[0])
    return (u, v)

def gen_weird_smooth_number(bits, prime_power):
    ...
    smooth = 8
    two_square = (2, 2)  # 2^2 + 2^2 = 8
    while smooth.bit_length() < bits:
        p = random.choice(list(prime_power.keys()))
        ...
        smooth *= p
        two_square = two_square_multiply(two_square, two_square_small(p))
    return smooth, two_square

def gen_weird_prime(bits, smooth_bound):
    prime_power = prepare_prime_power(smooth_bound)
    while True:
        s, (a, b) = gen_weird_smooth_number(bits, prime_power)
        assert a**2 + b**2 == s
        if number.isPrime(s - 2 * a + 1):
            break
        if number.isPrime(s - 2 * b + 1):
            a, b = b, a
            break
    return s - 2*a + 1

p = gen_weird_prime(512, 2**12)
q = number.getPrime(512)
n = p * q
```

This multiplies together random small primes up to `2**12` (squaring the ones that are `3 mod 4`, via the Brahmagupta-Fibonacci two-square composition identity `a^2+b^2` times `c^2+d^2` = another sum of two squares), producing a `2**12`-smooth number `s = u^2 + v^2`, then sets `p = s - 2u + 1` and requires it to be prime. `q` is an ordinary random 512-bit prime, and the flag is encrypted with RSA-OAEP using a random `e`:

```python
e = random.randint(2, phi-1)   # coprime to phi
...
c = cipher.encrypt(f.read().strip()).hex()
```

`output.txt` shows a standard-looking ~1024-bit modulus with no small factors and an unusually large, essentially random-looking `e` (not the usual `65537`):

```text
n = 4040627702512008464388858517030937894887360359453265765678943813...4569183050843414542262927839279957501
e = 1873849777726044589471569276863098312809573434700007871117786391...4221339073580100357237328499152850991845
c = 01beb55df5ad2cc5fd58c035ad28bc1cca99ad41d6ff57acd0a00ac323e1722753eb18a60f9f4b91ce8c6820ffb95c663f0a71bce594f492b1b324b3b1b3ccaa9e7c719425adc92f776782eadad6175a02de75af7f910de7d8be1357c82dc75222f9caeebf4f91774122b7f2741c629c8260d3716cd14ab140514a1c6954a9fcb4
```

`e` being unusual is a red herring for the attack: OAEP padding means bit-tricks on `e` don't matter, and the real weakness is entirely in how `p` was constructed - factoring `n` breaks the scheme regardless of `e`.

## Solve Path

`solve.sage`'s own comments spell out the number-theoretic structure: writing `p = (u-1)^2 + v^2 = U^2 + V^2` (with `U = u-1`, `V = v`),

```text
p + 1 + 2U = U^2+2U+1+V^2 = (U+1)^2+V^2 = u^2+v^2 = s
```

and `s` is smooth by construction. So `p + 1 + 2U` - the order of one of the quartic twists of the CM curve `E: y^2 = x^3 + A*x` (discriminant `-4`, `j = 1728`) modulo `p` - is smooth. That means an ECM-style attack using this specific curve family (rather than random Weierstrass curves) has a good chance of hitting the twist with smooth order and revealing a factor. Since discriminant `-4` has class number 1, no Hilbert class polynomial is needed - `j = 1728` directly gives the curve shape `y^2 = x^3 + A*x`.

The script first reconstructs the exact smoothness bound the challenge used, then builds `L`, a value guaranteed to be a multiple of the smooth twist order `s`:

```python
def prepare_prime_power(bound):
    # verbatim copy of factor_this.py's prepare_prime_power
    prime_power = {}
    for i in range(3, bound + 1):
        if is_prime(i):
            if i % 4 == 3:
                i = i ** 2
            exp = int(log(bound, i))
            if exp > 0:
                prime_power[i] = exp
    return prime_power

prime_power = prepare_prime_power(2 ** 12)
L = 1
for base, exp in prime_power.items():
    L *= base ** exp
```

It then implements the standard affine elliptic-curve group law over `Z/nZ`, deliberately without reducing modulo the (unknown) prime `p` - any time a slope's denominator shares a factor with `n`, that's a nontrivial divisor:

```python
def ec_add(n, P, Q, A):
    ...
    g = gcd(den, n)
    if g != 1:
        raise FactorFound(g)
    lam = (num * inverse_mod(den, n)) % n
    ...

def ec_mul(n, P, k, A):
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = ec_add(n, R, Q, A)
        Q = ec_add(n, Q, Q, A)
        k >>= 1
    return R
```

For each attempt, a random point `(x0, y0) mod n` is chosen and the curve coefficient `A` is derived algebraically so the point is guaranteed to lie on `y^2 = x^3 + A*x` - this implicitly samples a random twist of the CM curve:

```python
def find_factor(n, L, tries=100):
    for _ in range(tries):
        x0 = random.randrange(2, n)
        y0 = random.randrange(2, n)
        g = gcd(x0, n)
        if g != 1:
            return g
        A = ((y0 * y0 - x0 ** 3) * inverse_mod(x0, n)) % n
        try:
            ec_mul(n, (x0, y0), L, A)
        except FactorFound as e:
            if 1 < e.g < n:
                return e.g
    return None
```

Computing `[L]*(x0, y0)` under the group law mod `n`: on the twist whose order (mod `p`) divides `L` - the one built from the smooth `s` - the point reaches the identity modulo `p` partway through the multiplication, so some intermediate slope's denominator becomes divisible by `p`, and `gcd(den, n)` surfaces `p` (or `q`) directly. Once a factor `p` is found, `q = n // p` and standard RSA decryption follows:

```python
q = n // p
phi = (p - 1) * (q - 1)
d = inverse_mod(Integer(e), phi)
key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))
cipher = PKCS1_OAEP.new(key)
flag = cipher.decrypt(bytes.fromhex(c))
```

## Exploit

The solve script is [solve.sage](#Solve). It loads `n`, `e`, `c` from `output.txt`, rebuilds the same smoothness bound and multiplier `L` the challenge's prime generator implicitly used, repeatedly samples random points on random twists of a `j = 1728` CM curve mod `n` and multiplies by `L` until a group-law division fails (yielding a nontrivial factor of `n`), then reconstructs the RSA private key from the recovered `p`, `q` and decrypts the OAEP ciphertext.

Run:

```bash
sage solve.sage
```

Key helpers:

- `prepare_prime_power`: rebuilds the exact set of prime-power bases (squaring primes `3 mod 4`) the challenge's smooth-number generator drew from
- `load_output`: parses `n`, `e`, `c` out of `output.txt`
- `ec_add` / `ec_mul`: affine elliptic-curve point addition/doubling and scalar multiplication over `Z/nZ`, raising `FactorFound` whenever a slope denominator isn't invertible mod `n`
- `find_factor`: repeatedly samples a random point and derives its curve's `A` coefficient, then computes `[L]*point` until a factor drops out
- `main`: ties it together - factor `n`, derive `d`, reconstruct the RSA key, decrypt `c`

## Solve

```python=
# Factor this
#
# gen_weird_prime(512, 2**12) builds p as follows: pick random small primes
# q <= 4096 (squaring the ones that are 3 mod 4, so every factor has a
# two-square representation), multiply them together via the
# Brahmagupta-Fibonacci identity to get a SMOOTH number s = u^2+v^2 (all
# prime factors of s are <= 4096), then set p = s - 2*u + 1 = (u-1)^2 + v^2
# (or with u,v swapped) and require it to be prime.
#
# So p is a sum of two squares -- p = (u-1)^2 + v^2 -- which is exactly the
# condition for p to split in Z[i], i.e. the curve E: y^2 = x^3 + A*x
# (j-invariant 1728, CM by discriminant -4) has, for the right quartic
# twist, order EXACTLY equal to a nice value in terms of u,v. Concretely,
# writing p = U^2+V^2 with U=u-1, V=v:
#   p + 1 + 2U = U^2+2U+1+V^2 = (U+1)^2+V^2 = u^2+v^2 = s
# and s is smooth by construction! So one of the four twists of E has
# smooth order (=s) modulo p -- this is exactly the "hxp CTF 2021
# f_cktoring" style CM-curve ECM attack (here discriminant -4 has class
# number 1, so no Hilbert class polynomial / quotient ring is needed --
# j=1728 directly, curve y^2=x^3+A*x).
#
# Algorithm: replicate the challenge's own prepare_prime_power(2**12) to
# get the exact set of prime-power factors s could be built from, take
# L = product of (prime^max_exponent) over that set (guaranteed s | L),
# then repeatedly: pick a random point (x0,y0) mod n, derive the curve
# coefficient A from it (so the point is guaranteed to lie on curve
# y^2=x^3+A*x), and compute [L]*(x0,y0) using the standard (affine)
# elliptic-curve group law mod n. Whenever a slope's denominator is not
# invertible mod n, gcd(denominator, n) reveals a nontrivial factor of n
# (this happens as soon as the point becomes the identity mod p, i.e. on
# the lucky twist where the order divides L).

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import random

proof.all(False)


def prepare_prime_power(bound):
    # verbatim copy of factor_this.py's prepare_prime_power
    prime_power = {}
    for i in range(3, bound + 1):
        if is_prime(i):
            if i % 4 == 3:
                i = i ** 2
            exp = int(log(bound, i))
            if exp > 0:
                prime_power[i] = exp
    return prime_power


def load_output():
    with open("output.txt") as f:
        lines = f.read().splitlines()
    n = int(lines[0].split("=")[1].strip())
    e = int(lines[1].split("=")[1].strip())
    c = lines[2].split("=")[1].strip()
    return n, e, c


class FactorFound(Exception):
    def __init__(self, g):
        self.g = g


def ec_add(n, P, Q, A):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % n == 0:
            return None
        num = (3 * x1 * x1 + A) % n
        den = (2 * y1) % n
    else:
        num = (y2 - y1) % n
        den = (x2 - x1) % n

    g = gcd(den, n)
    if g != 1:
        raise FactorFound(g)

    lam = (num * inverse_mod(den, n)) % n
    x3 = (lam * lam - x1 - x2) % n
    y3 = (lam * (x1 - x3) - y1) % n
    return (x3, y3)


def ec_mul(n, P, k, A):
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = ec_add(n, R, Q, A)
        Q = ec_add(n, Q, Q, A)
        k >>= 1
    return R


def find_factor(n, L, tries=100):
    for _ in range(tries):
        x0 = random.randrange(2, n)
        y0 = random.randrange(2, n)

        g = gcd(x0, n)
        if g != 1:
            return g

        # pick A so that (x0,y0) lies on y^2 = x^3 + A*x
        A = ((y0 * y0 - x0 ** 3) * inverse_mod(x0, n)) % n

        try:
            ec_mul(n, (x0, y0), L, A)
        except FactorFound as e:
            if 1 < e.g < n:
                return e.g
    return None


def main():
    n, e, c = load_output()

    prime_power = prepare_prime_power(2 ** 12)
    L = 1
    for base, exp in prime_power.items():
        L *= base ** exp
    print("L bit length:", L.nbits())

    p = find_factor(n, L)
    if p is None:
        print("failed to find a factor -- try more attempts")
        return

    q = n // p
    assert p * q == n
    print("p =", p)
    print("q =", q)

    phi = (p - 1) * (q - 1)
    d = inverse_mod(Integer(e), phi)

    key = RSA.construct((int(n), int(e), int(d), int(p), int(q)))
    cipher = PKCS1_OAEP.new(key)
    flag = cipher.decrypt(bytes.fromhex(c))
    print(flag)


if __name__ == "__main__":
    main()
```

## Verification

```text
L bit length: 2992
p = 397027203605252264675763957065730438969375398813481501647604958549034889212975975417797859718447877204990680013475745377633484817470416389152278374130002757
q = 10177206160738138105690363514872404395390726313977034260792647319137154728798572421157077718831820356080366808567147739644498684413134448500806599980482393
b'HCMUS-CTF{Woa!!_you_know_a_lot_about_Elliptic_Curve}'
```

## Flag

```text
HCMUS-CTF{Woa!!_you_know_a_lot_about_Elliptic_Curve}
```

## Lessons Learned

- A prime built as a sum of two squares (`p = U^2 + V^2`) makes `p + 1 + 2U` (or `-2U`) the order of a twist of the CM curve `y^2 = x^3 + A*x` modulo `p` - if that quantity is smooth, the prime is factorable via ECM restricted to that curve family, regardless of how "random-looking" the modulus otherwise appears.
- Curves with complex multiplication (`j = 0` or `j = 1728`) let an attacker target a *specific, predictable* curve order formula instead of hoping a random Weierstrass curve's order happens to be smooth - this collapses generic ECM's randomness into a near-certain hit when the prime was built that way.
- In an ECM-style factorization, a scalar multiplication that fails partway through (a non-invertible slope denominator) is not a bug to work around - `gcd(denominator, n)` at that failure point *is* the factor.
- A large, "random-looking" public exponent `e` is not inherently suspicious under OAEP padding - don't assume unusual `e` is the intended weakness when the modulus construction itself is nonstandard.
- When a challenge's prime-generation routine is unusually elaborate (custom smooth-number construction, two-square composition, etc.), that complexity is almost always encoding a specific special-form-prime attack - replicate the generator's own parameters exactly (same smoothness bound, same prime-power set) rather than guessing bounds independently.
