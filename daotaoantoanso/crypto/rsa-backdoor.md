# RSA Backdoor Writeup

## Summary

This is an offline crypto challenge: `chal.py` prints a public modulus `n` and a ciphertext `ct` to `out.txt`, and there is no remote service to connect to. The core mechanic is that the second RSA prime `q` is derived from the first prime `p` by reinterpreting `p`'s decimal digit string in base 13, which makes `n = p * q` a strictly increasing, invertible function of `p` alone.

Flag:

```text
HCMUS-CTF{7h3_V3ry_f1r5t_4lg0r17hm_b1n4ry_534rch_w0www}
```

## Triage

`chal.py` generates the keypair with a backdoored relationship between the two primes instead of picking them independently:

```python
while True:
    p = getPrime(512)
    q = int(str(p), 13)
    if isPrime(q):
        n = p * q
        print('Public key n = ', n)
        break

print(f'ct = ', pow(bytes_to_long(FLAG), e, n))
```

`q = int(str(p), 13)` takes the base-10 digit string of `p` and reparses it as a base-13 integer - `q` is not an independently random 512-bit prime, it is a deterministic function of `p`'s digits. `e` is the standard `65537`.

`out.txt` contains only the public data:

```text
Public key n =  14072966033419198049110692513729221272039856578995770358978022374369702617407260974250371335874660886448635625415359435590866288684836396305467427652785918508438890316051644975416024575729239957690880362943383614229572482338338943926669325548496781092116918121854511282239218429506385724821682014631388855624828613598194700383
ct =  3297398274726419288742770485398984653524926733739942261260073512658711638212442235723491698663926587152143223728930627197111676440456437693388833394409296854208768556197435034647579096634751361373063515305871138820266505736702532043492078019209492809727200146481667680937461262102664960833393192739550652924626548337227957210
```

`n` is only a single ~1023-bit integer - no second modulus, no leaked bits, nothing else to work with - so the whole break has to come from the `q = f(p)` relationship baked into `n`'s construction.

## Solve Path

The key observation is that `f(p) = int(str(p), 13)` preserves numeric ordering: decimal digit-string order is the same as numeric order, and reinterpreting the same digit string in a larger base (13 > 10, and each digit stays `< 10`) keeps that order. So `g(p) = p * f(p) = n` is also strictly increasing in `p`, turning "factor `n`" into "invert a monotonic function of a single ~512-bit unknown" - solvable by binary search instead of any lattice/Coppersmith machinery:

```python
def q_from_p(p):
    return Integer(str(p), 13)

lo = Integer(2) ** 511
hi = Integer(2) ** 512 - 1

while lo < hi:
    mid = (lo + hi) // 2
    val = mid * q_from_p(mid)
    if val < n:
        lo = mid + 1
    else:
        hi = mid

p = lo
q = q_from_p(p)
assert p * q == n
assert is_prime(p) and is_prime(q)
```

Each iteration evaluates `g(mid) = mid * q_from_p(mid)` and compares it against `n`, halving the search interval `[2^511, 2^512)` every step until `p` is pinned down exactly. Once `p` is known, `q` follows immediately from the same digit-reinterpretation formula the challenge used, and the assertions confirm `p * q == n` with both factors prime.

With `p` and `q` recovered, this is now a normal RSA private-key derivation:

```python
phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
pt = power_mod(Integer(ct), Integer(d), Integer(n))
```

## Exploit

The solve script is [solve.sage](#Solve). It hardcodes `n`, `ct`, and `e` from `out.txt`, binary-searches for `p` using the monotonicity of `g(p) = p * q_from_p(p)`, derives `q` from `p`, computes `phi`, inverts `e` to get `d`, and decrypts `ct` directly.

Run:

```bash
sage solve.sage
```

Key steps:

- `q_from_p(p)`: reinterprets `p`'s decimal digits in base 13, mirroring the challenge's backdoor construction.
- binary search over `[2^511, 2^512 - 1]`: exploits monotonicity of `p * q_from_p(p)` to recover the exact `p` from `n` alone.
- `inverse_mod(e, phi)` + `power_mod`: standard RSA decryption once `p`, `q` are known.

## Sovle

```python=
# from out.txt
n = 14072966033419198049110692513729221272039856578995770358978022374369702617407260974250371335874660886448635625415359435590866288684836396305467427652785918508438890316051644975416024575729239957690880362943383614229572482338338943926669325548496781092116918121854511282239218429506385724821682014631388855624828613598194700383
ct = 3297398274726419288742770485398984653524926733739942261260073512658711638212442235723491698663926587152143223728930627197111676440456437693388833394409296854208768556197435034647579096634751361373063515305871138820266505736702532043492078019209492809727200146481667680937461262102664960833393192739550652924626548337227957210
e = 65537


def q_from_p(p):
    return Integer(str(p), 13)


# p = getPrime(512) -> p in [2^511, 2^512)
lo = Integer(2) ** 511
hi = Integer(2) ** 512 - 1

while lo < hi:
    mid = (lo + hi) // 2
    val = mid * q_from_p(mid)
    if val < n:
        lo = mid + 1
    else:
        hi = mid

p = lo
q = q_from_p(p)
assert p * q == n
assert is_prime(p) and is_prime(q)

phi = (p - 1) * (q - 1)
d = inverse_mod(e, phi)
pt = power_mod(Integer(ct), Integer(d), Integer(n))

flag = int(pt).to_bytes((int(pt).bit_length() + 7) // 8, "big")
print(flag)
```

## Verification

```text
b'HCMUS-CTF{7h3_V3ry_f1r5t_4lg0r17hm_b1n4ry_534rch_w0www}'
```

## Flag

```text
HCMUS-CTF{7h3_V3ry_f1r5t_4lg0r17hm_b1n4ry_534rch_w0www}
```

## Lessons Learned

- A prime-generation backdoor that makes one prime a deterministic function of the other collapses key generation from "factor a hard semiprime" to "invert a known function of one ~n/2-bit unknown."
- Monotonicity is a factoring oracle: if `n = g(p)` is strictly increasing in the single unknown `p`, binary search recovers `p` in `O(bits)` steps with no number-theoretic machinery at all.
- Digit-string reinterpretation across bases (e.g. base-10 digits read as base-`k`) preserves order whenever every digit stays below the smaller base - a property worth checking whenever a challenge derives one value from another's textual representation.
- Always inspect exactly how each RSA parameter is generated, not just its bit length - an innocuous-looking one-liner in keygen can be the entire vulnerability.
