# Polynomial PRNG Writeup

## Summary

Crypto challenge: each connection prints a fresh RSA `n, e, c` where `n = P1(x) * P2(x)` for two hidden degree-32 polynomials `P1, P2` and a per-connection random `x`. The two polynomials are fixed across reconnects and only `x` (a 24-bit value) varies, so ~90 samples of `n` let a solver recover the shared polynomial `R = P1*P2` by exact real-arithmetic interpolation - an RSA modulus generator where the "randomness" only ever touches one small, low-entropy parameter.

Flag:

```text
HCMUS-CTF{pOlYnOm1@l_F4ctOr1z@Ti0n_I$_e4$Y}
```

## Triage

`chal.py` generates each connection's keypair from two module-level secret polynomials (`secret_poly1`, `secret_poly2`, 33 coefficients each, degree 32, values in `[1, 2^32]`, imported from `poly.py`):

```python
from poly import secret_poly1, secret_poly2

def eval_poly(poly, x):
    res = 0
    for coef in poly:
        res = res * x + coef
    return res

while True:
    x = random.randint(2**23, 2**24)
    ...
    p = eval_poly(secret_poly1,x)
    q = eval_poly(secret_poly2,x)
    if isPrime(p) and isPrime(q):
        break

n = p * q
...
key = RSA.construct((n, e, d, p, q))
cipher = PKCS1_OAEP.new(key)
...
print(n, e, c)
```

`e` is a full-range random unit mod `phi` (no small-`e` weakness) and OAEP padding is used, so there's no textbook-RSA shortcut on a single sample. The only randomized input to `p, q` per connection is `x`, a value in `[2^23, 2^24)` - 24 bits - while the two polynomials that consume it never change between connections. `n` comes out to roughly 1560 bits, e.g. from a collected sample:

```
n = 2803245608569568862879496609088859799376310610074754401509...(≈480 digits)
```

## Solve Path

The exploration files in this folder show the path to that conclusion. `mt_verify.py` checked whether Python's `random` module (a Mersenne Twister) could be attacked directly - e.g. whether enough raw 32-bit words leak through calls like `getrandbits`/`randint` across connections to reconstruct MT state and predict future outputs:

```python
# Verify: given a value produced by getrandbits(k), can we recover the
# underlying raw genrand_uint32() words (all but the last, which is
# partially masked)?
```

This was a dead end for the real target: `chal.py` calls `random.randint(2**23, 2**24)` for `x` and a full-range `random.randint(2, phi-1)` for `e`, but MT-state recovery from `randint` calls would require many *consecutive* outputs from the *same* underlying stream - impractical here since the process is unpredictable per-connection and the payoff (predicting `x` before the server computes `p,q`) doesn't actually break anything even if achieved. `toy.py`/`toy2.py` explored the opposite angle at toy scale - brute-force DFS decomposition of a single `p` value into polynomial coefficients at a known `x`:

```python
def decompositions(value, x, d, C, max_results=5):
    # find up to max_results tuples (a_0..a_d), 1<=a_i<=C, with
    # eval_poly(a,x) == value, via DFS with pruning on remaining range
```

That only works at toy parameters (`d=4`, `C=2^6`); at the real scale (`d=32`, `C=2^32`) the search space is far too large. `probe.sage` then asked the actual precondition question needed before any cross-connection attack made sense - are the polynomials fixed across reconnects?

```python
# Every theory for attacking this (Lagrange interpolation across samples,
# birthday/GCD collisions, etc.) hinges on one unknown fact: are
# secret_poly1/secret_poly2 (from poly.py) FIXED across reconnects...
```

With that confirmed, `toy3.sage` validated the real technique end-to-end at production scale on synthetic data before spending live connections, and `solve.sage` implements it against `samples.jsonl` collected by `collect.py`. The core idea: `n = P1(x)*P2(x) = R(x)` for a single fixed degree-64 polynomial `R`; taking a high-precision 64th root of each `n_i` gives `r_i ≈ alpha*x_i + gamma` where `alpha, gamma` are the same constants for every sample:

```python
RF = RealField(PREC_BITS)
rs = [RF(n) ** (RF(1) / DEG) for n in n_list]

ref = min(range(N), key=lambda i: rs[i])
Ds = [rs[i] - rs[ref] for i in range(N)]
```

Differencing against a reference sample cancels `gamma`, leaving each `D_i` as (to high precision) an integer multiple of the single shared real `alpha`. Continued-fraction rational reconstruction on a ratio of two large-offset differences recovers a coprime pair of offsets, which pins down `alpha` to ~55 bits:

```python
def recover_alpha(Ds, order):
    for ii in range(len(order)):
        for jj in range(ii + 1, len(order)):
            i, j = order[ii], order[jj]
            Di, Dj = Ds[i], Ds[j]
            frac = (Di / Dj).nearby_rational(max_denominator=2 ** 25)
            p = frac.numerator()
            V = Di / p
            if 1 <= V < 2:
                return V, (i, j)
```

Every sample's exact integer offset from the reference then follows by rounding `D_i / alpha`, which turns 65+ `(offset_i, n_i)` pairs into exact interpolation points for `S(t) = R(t + x_ref)`:

```python
S = PR.lagrange_polynomial([(offsets[i], n_list[i]) for i in interp_idx])

held_ok = all(S(offsets[i]) == n_list[i] for i in holdout_idx)
```

That held-out check - predicting unseen samples' 1560-bit `n` values exactly with an interpolated degree-64 integer polynomial - is the correctness oracle before trusting anything further. Once `S` is confirmed, it factors over `Z` into the two degree-32 secret polynomials (shifted by the unknown `x_ref`), and evaluating those factors at a target sample's offset recovers that sample's `p, q` directly via gcd with its `n`:

```python
fac = ZR(S).factor()
factors = [f for f, e in fac for _ in range(e)]
...
for f in factors:
    g = gcd(Integer(f(off_t)), n_t)
    if 1 < g < n_t:
        p = g
        break
q = n_t // p
d = inverse_mod(e_t, (p - 1) * (q - 1))
```

From there it's a standard RSA private-key reconstruction and OAEP decrypt.

## Exploit

[solve.sage](#Solve) reads `samples.jsonl` (collected beforehand by [collect.py](#Collect) making ~90 live connections), recovers the shared scaling constant `alpha` and each sample's integer offset from a reference, Lagrange-interpolates the fixed degree-64 product polynomial, validates it against held-out samples, factors it over Z to recover a target sample's `p` and `q`, and OAEP-decrypts that sample's flag ciphertext. Run with:

```
sage solve.sage
```

Key functions/steps:
- `load_samples()` - parses `(n, e, c)` triples out of `samples.jsonl`
- `recover_alpha(Ds, order)` - continued-fraction search over large-offset difference pairs for the shared real scaling constant `alpha`
- high-precision `RF(n) ** (RF(1)/DEG)` root extraction + reference-differencing - turns hidden `x_i` into recoverable linear offsets
- `PR.lagrange_polynomial(...)` - exact interpolation of `S(t) = R(t + x_ref)` from 65 offset/`n` pairs
- held-out check (`S(offsets[i]) == n_list[i]`) - correctness oracle before proceeding
- `ZR(S).factor()` - factors the interpolated polynomial into the two secret degree-32 factors
- gcd of a factor evaluated at a target offset against that sample's `n` - recovers `p`, then `q = n // p`
- `RSA.construct(...)` + `PKCS1_OAEP` decrypt - final flag recovery

## Collect 

```python=
from pwn import *
import json
import os
import time

context.log_level = "error"

HOST = "vm.daotao.antoanso.org"
PORT = 32769  # TODO: set the real port

TARGET = 90   # need 65 to interpolate deg-64 R; extra for alpha + held-out
OUTFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "samples.jsonl")


def load_count():
    if not os.path.exists(OUTFILE):
        return 0
    with open(OUTFILE) as f:
        return sum(1 for line in f if line.strip())


def get_one():
    io = remote(HOST, PORT)
    line = io.recvline().decode().strip()
    io.close()
    parts = line.split()
    n, e, c = parts[0], parts[1], parts[2]
    int(n)
    int(e)
    bytes.fromhex(c)  # validate parse
    return n, e, c


def main():
    have = load_count()
    print(f"already have {have} samples, target {TARGET}")
    with open(OUTFILE, "a") as f:
        while have < TARGET:
            t0 = time.time()
            try:
                n, e, c = get_one()
            except Exception as ex:
                print("  retry after error:", ex)
                time.sleep(2)
                continue
            f.write(json.dumps({"n": n, "e": e, "c": c}) + "\n")
            f.flush()
            have += 1
            print(f"[{have}/{TARGET}] {time.time() - t0:.1f}s  "
                  f"n.bits={int(n).bit_length()}")
    print("done -- run solve.sage next")


if __name__ == "__main__":
    main()
```

## Solve

```python=
import json
import os

DEG = 64
PREC_BITS = 800
INTERP_PTS = 65
SAMPLES_FILE = os.path.join(os.path.dirname(os.path.abspath(
    __file__)) if "__file__" in dir() else ".", "samples.jsonl")


def load_samples():
    path = SAMPLES_FILE
    if not os.path.exists(path):
        path = "samples.jsonl"
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            out.append((Integer(o["n"]), Integer(o["e"]), o["c"]))
    return out


def recover_alpha(Ds, order):
    # try pairs among the largest-offset samples until one is coprime
    for ii in range(len(order)):
        for jj in range(ii + 1, len(order)):
            i, j = order[ii], order[jj]
            Di, Dj = Ds[i], Ds[j]
            if Dj == 0:
                continue
            frac = (Di / Dj).nearby_rational(max_denominator=2 ** 25)
            p = frac.numerator()
            if p == 0:
                continue
            V = Di / p
            if 1 <= V < 2:
                return V, (i, j)
    return None, None


def main():
    samples = load_samples()
    N = len(samples)
    print(f"loaded {N} samples")
    if N < INTERP_PTS + 3:
        print(f"need at least {INTERP_PTS + 3} samples; collect more")
        return

    n_list = [s[0] for s in samples]
    e_list = [s[1] for s in samples]
    c_list = [s[2] for s in samples]

    RF = RealField(PREC_BITS)
    print("computing high-precision 64th roots...")
    rs = [RF(n) ** (RF(1) / DEG) for n in n_list]

    ref = min(range(N), key=lambda i: rs[i])
    Ds = [rs[i] - rs[ref] for i in range(N)]
    order = sorted(range(N), key=lambda i: -abs(Ds[i]))

    alpha, info = recover_alpha(Ds, order[:20])
    if alpha is None:
        print("!! no coprime pair found among largest offsets -- collect more")
        return
    print(f"recovered alpha via coprime pair {info}: {alpha}")

    offsets = [int((Ds[i] / alpha).round()) for i in range(N)]

    # dedupe by offset (x-collisions across samples are rare but possible),
    # keeping distinct offsets for interpolation
    seen = {}
    for i in range(N):
        if offsets[i] not in seen:
            seen[offsets[i]] = i
    distinct = list(seen.values())
    print(f"{len(distinct)} distinct offsets available")
    if len(distinct) < INTERP_PTS + 1:
        print("not enough distinct offsets; collect more")
        return

    interp_idx = distinct[:INTERP_PTS]
    holdout_idx = distinct[INTERP_PTS:]

    PR = PolynomialRing(QQ, 't')
    print(f"interpolating degree-{DEG} S(t) from {INTERP_PTS} points...")
    S = PR.lagrange_polynomial([(offsets[i], n_list[i]) for i in interp_idx])
    print("deg S:", S.degree())

    # correctness oracle: predict held-out samples exactly
    held_ok = all(S(offsets[i]) == n_list[i] for i in holdout_idx)
    print(f"held-out check on {len(holdout_idx)} unseen samples:", held_ok)
    if not held_ok:
        print("!! held-out check FAILED -- an offset is wrong or model error "
              "too large. Collect more samples / raise PREC_BITS.")
        return

    print("factoring S over Z...")
    ZR = PolynomialRing(ZZ, 't')
    fac = ZR(S).factor()
    factors = [f for f, e in fac for _ in range(e)]
    print("factor degrees:", [f.degree() for f in factors])

    # decrypt: pick a target sample, get its p,q by evaluating factors at its
    # offset and gcd-ing with n, then OAEP-decrypt its c
    t = interp_idx[0]
    n_t, e_t, c_t = n_list[t], e_list[t], c_list[t]
    off_t = offsets[t]

    p = None
    for f in factors:
        g = gcd(Integer(f(off_t)), n_t)
        if 1 < g < n_t:
            p = g
            break
    if p is None:
        print("!! could not peel a prime factor from the target sample")
        return
    q = n_t // p
    assert p * q == n_t, "factorization mismatch"
    print("p =", p)
    print("q =", q)

    d = inverse_mod(e_t, (p - 1) * (q - 1))

    try:
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        key = RSA.construct((int(n_t), int(e_t), int(d), int(p), int(q)))
        cipher = PKCS1_OAEP.new(key)
        flag = cipher.decrypt(bytes.fromhex(c_t))
        print("FLAG:", flag)
    except Exception as ex:
        print("OAEP decrypt in sage failed:", ex)
        print("Recovered private params -- decrypt with pycryptodome directly:")
        print("n =", n_t)
        print("e =", e_t)
        print("d =", d)
        print("p =", p)
        print("q =", q)
        print("c =", c_t)


if __name__ == "__main__":
    main()
```

## Verification

```text
loaded 90 samples
computing high-precision 64th roots...
recovered alpha via coprime pair (47, 64): 1.91263924558460942283882846844633701647966730166081117206140180344059658940340947663816716483231389753502658876957436894400419142875667645278571563185642682930861175779984512122338056417630936278500668941363227996071311681909614279108380901
84 distinct offsets available
interpolating degree-64 S(t) from 65 points...
deg S: 64
held-out check on 19 unseen samples: True
factoring S over Z...
factor degrees: [32, 32]
p = 172718756888684441614458533448318805947478548259953661188591874274773263665980946689397594263636645955698024544741362404929120756755614632329223475266918515013175301610447460318583198586193510699127501394482405735102770151627656796309093
q = 1623011686203967635107538006161175911900432380641226525367325161241529890823134646454560833734481988964581474465900492119538641269974928418272800665743730235854448752198944105475902283313430518447159145025178850280220251187175213920549669
FLAG: b'HCMUS-CTF{pOlYnOm1@l_F4ctOr1z@Ti0n_I$_e4$Y}\r\n'
```

## Flag

```text
HCMUS-CTF{pOlYnOm1@l_F4ctOr1z@Ti0n_I$_e4$Y}
```

## Lessons Learned

- Reusing fixed secret parameters (here, two polynomials) across many otherwise-independent instances turns a single "hard" instance into a data-collection problem - enough samples make the shared structure solvable even if any one sample alone is secure.
- When only a small-entropy value differs between samples of a larger deterministic function, high-precision real arithmetic (roots, differences) can recover that value's *relationship* across samples even without ever seeing it directly.
- Continued-fraction / rational-reconstruction techniques let you pull exact small integers or exact ratios out of approximate high-precision real quantities - useful whenever a noisy real-valued observable is secretly linear in unknown integers.
- Always validate a recovered model against held-out data before trusting it for the final step - an interpolated polynomial that also predicts unseen large values is strong evidence of correctness, not a coincidence.
- Before designing an attack, test the precondition it depends on (e.g. "are these secrets actually fixed across connections?") with a cheap probe rather than assuming it.
