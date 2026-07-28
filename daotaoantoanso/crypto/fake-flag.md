# Fake Flag Writeup

## Summary

Local, offline crypto challenge - only `fake_flag.py` (source) and `output.txt` (generated data) are provided, no remote connection. The flag is encoded as a large integer `a` and scrambled through `a^p - k^p` and `a^q - k^q` for two small primes `p`, `q` and a random secret `k`; the core weakness is that `A^n - B^n` is always divisible by `A - B`, so `a - k` can be pulled out as a shared algebraic factor of the two power differences via `gcd`, then combined with the directly-leaked `k`, `r`, and `d` values to recover the flag modulo `r`, with the final exact value pinned down by brute-forcing against the flag's known prefix format.

Flag:

```text
0160ca14{This_is_fake_flag_hahaha!}
```

## Triage

`fake_flag.py` converts the flag to an integer and mixes it with a random secret `k` through two prime-power differences:

```python
FLAG = b"0160ca14{?????????????????????????}"

p = getPrime(16)
q = getPrime(16)
assert p != q

r = getPrime(256)

a = bytes_to_long(FLAG)

k = randint(1, r-1)

x = a**p-k**p
y = a**q-k**q
```

It then reduces those two large differences down to a single leaked value `number`, via a small-divisor extraction and a `gcd`:

```python
def find_small_divisor(number: int):
    divisor = 10
    while(number%divisor != 0):
        divisor += 1
    return divisor

d = find_small_divisor(gcd(x+y, x))
number = (k*gcd((x+y)//d, y//d)) % r
```

`output.txt` prints `p`, `q`, `r`, `k`, `d`, and `number` in full - every parameter except `x`, `y`, and `a` (the flag itself) is handed over directly:

```text
p = 50969
q = 48859
r = 90254724465230431478307125031992674356849799682990984954478193657616557516363
k = 77613813229115705407983120551706296959236412766954020268752564135993144643307
d = 2111
number = 55082456475351903378255749118970454587034932966959264607612363109719848202778
```

`p` and `q` are only 16-bit primes and `r` is a 256-bit prime - small enough parameters that the interesting structure is entirely in how `x`, `y`, `d`, and `number` were derived from `a` and `k`, not in factoring anything.

## Solve Path

For a prime exponent `n`, `A^n - B^n` always factors as `(A - B) * sum_{i=0}^{n-1} A^i B^{n-1-i}`. Applied here:

```text
x = a**p - k**p = (a - k) * S_p
y = a**q - k**q = (a - k) * S_q
x + y = (a - k) * (S_p + S_q)
```

so `(a - k)` is a common factor of `x` and `x + y`, meaning `gcd(x + y, x)` retains `(a - k)` times whatever common factor `S_p` and `S_q` happen to share. `find_small_divisor` peels off that small extraneous common factor as `d`, and the challenge exposes `number = k * gcd((x+y)//d, y//d) mod r` as the only value tying back to `a`.

Since `k`, `d`, and `r` are all given directly in `output.txt`, the residual `gcd`-derived quantity can be inverted straight back to `a - k` (and hence `a`) modulo `r`:

```python
k_inv = pow(k, -1, r)
a_gcd = (number * k_inv * d) % r
a_sus = (a_gcd + k) % r
```

`a_sus` is only `a mod r` - the real flag integer `a` (35 bytes, larger than the 256-bit `r`) is `a_sus + m*r` for some unknown small multiplier `m`. Because the flag's format is known (`0160ca14{...}`, 35 bytes total), the correct `m` is found by locating the smallest candidate at or above the minimal integer that starts with the known prefix:

```python
prefix = b"0160ca14{"
total_length = 35
suffix_length = total_length - len(prefix)

min_a = int.from_bytes(prefix + b"\x00" * suffix_length, 'big')

m = (min_a - a_sus) // r
if a_sus + m * r < min_a:
    m += 1

a = a_sus + m * r
flag = long_to_bytes(a)
```

Note that `solve.py` references `p`, `q`, `r`, `k`, `d`, and `number` without ever defining or importing them - it is written to be run in a namespace where `output.txt`'s assignment statements have already been evaluated (e.g. `python3 -c "exec(open('output.txt').read()); exec(open('solve.py').read())"`), since `output.txt`'s contents are themselves valid Python assignments.

## Exploit

[solve.py](#Solve) takes the leaked `k`, `r`, `d`, and `number` from `output.txt`, inverts `k` mod `r` to recover `a mod r`, then brute-forces the correct multiple of `r` to add using the known `0160ca14{...}` prefix and fixed flag length, printing the recovered flag bytes.

Run (loading `output.txt`'s values into the same namespace first):

```bash
python3 -c "exec(open('output.txt').read()); exec(open('solve.py').read())"
```

Key steps:

- `k_inv`: modular inverse of the leaked `k` mod `r`, used to undo the `k * (...)` scaling in `number`.
- `a_gcd` / `a_sus`: recovers `a mod r` from `number` by undoing the `k` scaling and the `d` division, then adding back `k`.
- `min_a`: the smallest integer whose big-endian bytes start with the known flag prefix and match the known total flag length.
- `m`: the multiplier on `r` that lifts `a_sus` up to the correct absolute value of `a`, found by rounding `(min_a - a_sus) / r` up to the nearest integer that doesn't undershoot `min_a`.

## Solve

```python=
from Crypto.Util.number import long_to_bytes

# from output.txt
p = 50969
q = 48859
r = 90254724465230431478307125031992674356849799682990984954478193657616557516363
k = 77613813229115705407983120551706296959236412766954020268752564135993144643307
d = 2111
number = 55082456475351903378255749118970454587034932966959264607612363109719848202778

k_inv = pow(k, -1, r)
a_gcd = (number * k_inv * d) % r
a_sus = (a_gcd + k) % r

prefix = b"0160ca14{"
total_length = 35 
suffix_length = total_length - len(prefix)

min_a = int.from_bytes(prefix + b"\x00" * suffix_length, 'big')

m = (min_a - a_sus) // r
if a_sus + m * r < min_a:
    m += 1

a = a_sus + m * r
flag = long_to_bytes(a)

print(f"Recovered Flag: {flag.decode()}")
```

## Verification

```text
Recovered Flag: 0160ca14{This_is_fake_flag_hahaha!}
```

## Flag

```text
0160ca14{This_is_fake_flag_hahaha!}
```

## Lessons Learned

- `A^n - B^n` is always divisible by `A - B` for any exponent `n`; taking the `gcd` of two such differences sharing the same `A - B` (but different exponents) is a way to recover that common factor without knowing `A` or `B` individually.
- Leaking a value modulo a modulus smaller than the secret itself only pins the secret down to a residue class - recovering the exact value needs either a known format/prefix to brute-force the multiplier, or extra congruences (CRT) to extend the modulus.
- Watch for solve scripts that assume prior state (variables from a companion data file) rather than loading it themselves - always check for a missing `open()`/`import` before assuming a script is broken.
- Encoding a flag as one large integer straddling a scrambling modulus is a common way to keep an "encryption" scheme partially reversible while still requiring an extra reconstruction step at the end.
- When several of a scheme's "secret" parameters are printed directly in the output, treat that as a strong signal that the real difficulty lies in inverting the specific algebraic combination they were fed into, not in any missing-value brute force.
