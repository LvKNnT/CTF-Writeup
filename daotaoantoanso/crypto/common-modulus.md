# Common Modulus Writeup

## Summary

This is an offline crypto challenge: `problem.py` is a standalone generator that writes `output.txt` (`n`, the list of primes `l`, and the ciphertext list `C`) with no server or socket involved - everything needed to solve it is in the provided files. The flag is RSA-encrypted eight times under a single modulus `n` with eight different exponents built from the same set of coprime primes, so the exponents have `gcd == 1` and the flag can be recovered directly via a generalized extended-Euclidean (Bezout) combination, with no factoring of `n` required.

Flag:

```text
HCMUS-CTF{3xtended_Euclidean_A1g0rithm}
```

## Triage

`problem.py` builds a 4096-bit RSA modulus from two independent 2048-bit primes, then picks 8 random 32-bit primes `l[0..7]`:

```python
k = 8
n = getPrime(2048)*getPrime(2048)
print(f"n = {n}")

l = [getPrime(32) for i in range(k)]
print(f"l = {l}")

C = []
for i in range(k):
    li = l[:i] + l[i+1:]
    e = math.prod(li)
    C.append(pow(flag, e, n))
```

For each index `i`, the exponent `e_i` is the product of all `l[j]` for `j != i` (i.e. the flag is raised to the product of 7 of the 8 primes, omitting the `i`-th one), and `C[i] = flag**e_i mod n`. `output.txt` confirms the shape of the data:

```text
n = 940061047059693065742464365398262241290752444593296314948723840987...843965899157
l = [3103306147, 3734885419, 2365514209, 3527164493, 3072050083, 4131822407, 2509876661, 3783867877]
C = [33613942184753110906623350176637819858860556977699565094572811729...5488080618268, ...]
```

`n` is an unstructured 4096-bit RSA modulus (no small factors, no shared primes) - factoring is not the intended path. The weak point is the *set of exponents*: because `l` consists of 8 distinct primes, each `e_i` is missing exactly the factor `l[i]` that every other `e_j` (`j != i`) still contains. No single prime divides all 8 exponents simultaneously, so `gcd(e_0, ..., e_7) == 1`.

## Solve Path

The generator's own code is echoed to reconstruct the exponents exactly as `problem.py` computed them:

```python
k = len(l)
e = [math.prod(l[:i] + l[i + 1:]) for i in range(k)]
```

Since `gcd(e_0, ..., e_7) == 1`, Bezout's identity guarantees integers `a_0..a_7` with `sum(a_i * e_i) == 1`. These are found by chaining the extended Euclidean algorithm pairwise across all 8 exponents, accumulating the combined coefficients as each new exponent is folded in:

```python
def xgcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t   # g == a*old_s + b*old_t


g = e[0]
coeffs = [1]
for i in range(1, k):
    g, x, y = xgcd(g, e[i])
    coeffs = [c * x for c in coeffs]
    coeffs.append(y)

assert g == 1, f"gcd of exponents wasn't 1: {g}"
```

With `sum(a_i * e_i) == 1` established, `flag**1 = flag**(sum a_i*e_i) = prod (flag**e_i)**a_i = prod C[i]**a_i (mod n)`. Since `C[i]` is already `flag**e_i mod n`, this recovers the flag directly by combining all 8 ciphertexts with modular exponentiation (negative `a_i` are handled transparently by Python/Sage's `pow(base, exp, mod)`, which supports negative exponents when `base` is invertible mod `n`):

```python
flag_int = 1
for ci, ai in zip(C, coeffs):
    flag_int = (flag_int * pow(ci, ai, n)) % n

flag_bytes = int(flag_int).to_bytes((int(flag_int).bit_length() + 7) // 8, "big")
print(flag_bytes)
```

No factoring of the 4096-bit `n` is ever needed - the attack works entirely modulo `n` using only the coprimality of the exponents.

## Exploit

The solve script is [solve.sage](#Solve). It reads `n`, `l`, and `C` (hardcoded from `output.txt`), reconstructs the 8 exponents `e_i` exactly as the challenge did, runs a chained extended-Euclidean reduction to find Bezout coefficients summing the exponents to 1, and combines the ciphertexts with those coefficients as modular exponents to recover the flag integer.

Run:

```bash
sage solve.sage
```

Key steps:

- `xgcd`: standard extended Euclidean algorithm, returns `(gcd, s, t)` such that `gcd == a*s + b*t`
- chained loop over `e[1:]`: folds each new exponent into the running gcd/coefficient set so the final `coeffs` list satisfies `sum(coeffs[i] * e[i]) == 1`
- final combination loop: multiplies `pow(C[i], coeffs[i], n)` across all 8 ciphertexts mod `n` to recover `flag_int`

## Verification

```text
b'HCMUS-CTF{3xtended_Euclidean_A1g0rithm}'
```

## Flag

```text
HCMUS-CTF{3xtended_Euclidean_A1g0rithm}
```

## Lessons Learned

- Reusing the same message/plaintext under multiple exponents modulo a common `n` is dangerous even without a shared modulus between two RSA keys in the classical sense - if the exponents used are collectively coprime (`gcd == 1`), the message can be recovered by a Bezout combination of the ciphertexts.
- The extended Euclidean algorithm generalizes cleanly from two values to `k` values by chaining pairwise `xgcd` calls and folding the coefficient lists together.
- `pow(base, exp, mod)` with a negative `exp` works directly in Python/Sage as long as `base` is invertible mod `mod` - no need to manually compute modular inverses when Bezout coefficients come out negative.
- Before reaching for factoring tools on a large modulus, check whether the *exponents* themselves have exploitable structure (shared factors, coprimality, small size) - many "common modulus"-style attacks never touch the modulus's factorization at all.
- Deliberately weak exponent construction (e.g. "omit one prime from the product") can silently guarantee coprimality across all instances - always compute `gcd` across leaked/derived exponents when a message is encrypted multiple times.
